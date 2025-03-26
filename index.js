import process from 'process';
import { MongoClient } from 'mongodb';
import express from 'express';
import bcrypt from 'bcryptjs';
import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import nodemailer from 'nodemailer';


const MONGO_URI = 'mongodb+srv://mike:123@f1.4qx3rrg.mongodb.net/?retryWrites=true&w=majority&appName=F1';
const JWT_SECRET = 'holaaaa123';

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
      user: 'ms462974@gmail.com', 
      pass: 'xsuh uqqj ohpi dvxs' 
  }
});

async function connectToMongo() {
  try {
    const client = new MongoClient(MONGO_URI);
    await client.connect();
    console.log('✅ MongoDB connected successfully');
    return client;
  } catch (error) {
    console.error('❌ MongoDB connection failed:', error);
    process.exit(1);
  }
}

async function startServer() {
  try {
    const mongoClient = await connectToMongo();
    const app = express();

    app.use(cors());
    app.use(express.json());

    const PORT = process.env.PORT || 5000;

    app.post('/api/login', async (req, res) => {
        const { correo, contraseña } = req.body;
    
        try {
            const user = await mongoClient.db().collection('users').findOne({ correo });
            if (!user) {
                return res.status(400).json({ error: 'Usuario no encontrado' });
            }
    
            const passwordMatch = await bcrypt.compare(contraseña, user.contraseña);
            if (!passwordMatch) {
                return res.status(400).json({ error: 'Contraseña incorrecta' });
            }
    
            // Generamos un nuevo secreto para MFA cada vez que el usuario inicie sesión
            const secret = speakeasy.generateSecret({ name: 'MyApp' });
            
            // Guardamos el secreto en la base de datos (si es la primera vez que el usuario inicia sesión con MFA)
            await mongoClient.db().collection('users').updateOne(
                { correo },
                { $set: { mfaSecret: secret.base32 } } // Guardamos el secreto en la base de datos
            );
    
            // Generamos el código QR
            const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);
    
            // Devolvemos el código QR al frontend
            return res.status(200).json({ message: 'Configura MFA', qrCodeUrl });
        } catch (error) {
            console.error('Error en el login:', error);
            res.status(500).json({ error: 'Error al iniciar sesión' });
        }
    });
    

    // 📌 API para solicitar recuperación de contraseña
app.post('/api/forgot-password', async (req, res) => {
  const { correo } = req.body;
  try {
      const user = await mongoClient.db().collection('users').findOne({ correo });
      if (!user) return res.status(400).json({ error: 'Correo no registrado' });

      // Generar un código aleatorio de 6 dígitos
      const resetCode = Math.floor(100000 + Math.random() * 900000).toString();

      // Guardar el código en la base de datos
      await mongoClient.db().collection('users').updateOne({ correo }, { $set: { resetCode } });

      // Enviar correo con el código
      await transporter.sendMail({
          from: 'tuemail@gmail.com',
          to: correo,
          subject: 'Código de recuperación de contraseña',
          text: `Tu código de recuperación es: ${resetCode}`
      });

      res.status(200).json({ message: 'Código enviado al correo' });
  } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Error enviando el código' });
  }
});

// 📌 API para restablecer la contraseña
app.post('/api/reset-password', async (req, res) => {
  const { correo, resetCode, nuevaContraseña } = req.body;

  try {
      const user = await mongoClient.db().collection('users').findOne({ correo });

      if (!user || user.resetCode !== resetCode) {
          return res.status(400).json({ error: 'Código incorrecto o expirado' });
      }

      // Hashear la nueva contraseña
      const hashedPassword = await bcrypt.hash(nuevaContraseña, 10);

      // Actualizar la contraseña y eliminar el código de recuperación
      await mongoClient.db().collection('users').updateOne(
          { correo },
          { $set: { contraseña: hashedPassword }, $unset: { resetCode: 1 } }
      );

      res.status(200).json({ message: 'Contraseña actualizada correctamente' });
  } catch (error) {
      console.error(error);
      res.status(500).json({ error: 'Error al actualizar la contraseña' });
  }
});

    // 📌 API para verificar el código MFA
    app.post('/api/verify-mfa', async (req, res) => {
      const { correo, code } = req.body;

      try {
        const user = await mongoClient.db().collection('users').findOne({ correo });
        if (!user || !user.mfaSecret) {
          return res.status(400).json({ error: 'MFA no configurado o no disponible' });
        }

        // Verificamos el código TOTP
        const isValid = speakeasy.totp.verify({
          secret: user.mfaSecret,
          encoding: 'base32',
          token: code,
          window: 1, // Permite 1 código fuera de tiempo de tolerancia
        });

        if (!isValid) {
          return res.status(400).json({ error: 'Código MFA incorrecto' });
        }

        // Si es válido, generar JWT
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });

        res.status(200).json({ message: 'Autenticación exitosa', token });
      } catch (error) {
        res.status(500).json({ error: 'Error al verificar el código MFA' });
      }
    });

    const server = app.listen(PORT, () => {
      console.log(`✅ Server running on port ${PORT}`);
    });

    process.on('SIGINT', async () => {
      console.log('\n🔴 Closing MongoDB connection...');
      await mongoClient.close();
      process.exit(0);
    });

    return { app, mongoClient, server };
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

startServer();

export { connectToMongo, startServer };
