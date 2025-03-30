import { MongoClient, ObjectId } from 'mongodb';
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

// Initialize MongoDB connection
let cachedClient = null;
let cachedDb = null;

async function connectToMongo() {
  if (cachedClient && cachedDb) {
    return { client: cachedClient, db: cachedDb };
  }

  try {
    const client = new MongoClient(MONGO_URI);
    await client.connect();
    const db = client.db('test');
    
    cachedClient = client;
    cachedDb = db;
    
    return { client, db };
  } catch (error) {
    console.error('MongoDB connection failed:', error);
    throw error;
  }
}

// Create Express app
const app = express();

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization'],
  preflightContinue: false,
  optionsSuccessStatus: 204
}));

app.use(express.json());

// Define routes
app.get('/', (req, res) => {
  res.send('Hello from the server!');
});

// Register route
app.post('/api/register', async (req, res) => {
  try {
    const { nombre, correo, contraseña } = req.body;
    const { db } = await connectToMongo();
    const usersCollection = db.collection('users');

    const existingUser = await usersCollection.findOne({ correo });
    if (existingUser) {
      return res.status(400).json({ error: 'El correo ya está registrado' });
    }

    const hashedPassword = await bcrypt.hash(contraseña, 10);
    const newUser = { nombre, correo, contraseña: hashedPassword };
    await usersCollection.insertOne(newUser);

    res.status(201).json({ message: 'Usuario registrado correctamente' });
  } catch (error) {
    console.error('Error al registrar usuario:', error);
    res.status(500).json({ error: 'Error al registrar usuario' });
  }
});

// Login route
app.post('/api/login', async (req, res) => {
  const { correo, contraseña } = req.body;

  try {
    const { db } = await connectToMongo();
    const user = await db.collection('users').findOne({ correo });
    if (!user) {
      return res.status(400).json({ error: 'Usuario no encontrado' });
    }

    const passwordMatch = await bcrypt.compare(contraseña, user.contraseña);
    if (!passwordMatch) {
      return res.status(400).json({ error: 'Contraseña incorrecta' });
    }
    
    const secret = speakeasy.generateSecret({ name: 'MyApp' });
    
    await db.collection('users').updateOne(
      { correo },
      { $set: { mfaSecret: secret.base32 } } 
    );

    const qrCodeUrl = await qrcode.toDataURL(secret.otpauth_url);
    return res.status(200).json({ message: 'Configura MFA', qrCodeUrl });
  } catch (error) {
    console.error('Error en el login:', error);
    res.status(500).json({ error: 'Error al iniciar sesión' });
  }
});

// Forgot password route
app.post('/api/forgot-password', async (req, res) => {
  const { correo } = req.body;
  try {
    const { db } = await connectToMongo();
    const user = await db.collection('users').findOne({ correo });
    if (!user) return res.status(400).json({ error: 'Correo no registrado' });

    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();
    await db.collection('users').updateOne({ correo }, { $set: { resetCode } });

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

// Reset password route
app.post('/api/reset-password', async (req, res) => {
  const { correo, resetCode, nuevaContraseña } = req.body;

  try {
    const { db } = await connectToMongo();
    const user = await db.collection('users').findOne({ correo });

    if (!user || user.resetCode !== resetCode) {
      return res.status(400).json({ error: 'Código incorrecto o expirado' });
    }

    const hashedPassword = await bcrypt.hash(nuevaContraseña, 10);
    await db.collection('users').updateOne(
      { correo },
      { $set: { contraseña: hashedPassword }, $unset: { resetCode: 1 } }
    );

    res.status(200).json({ message: 'Contraseña actualizada correctamente' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al actualizar la contraseña' });
  }
});

// Report route
app.post('/api/report', async (req, res) => {
  const { name, email, description } = req.body;

  if (!name || !email || !description) {
    return res.status(400).json({ error: 'Todos los campos son obligatorios' });
  }

  try {
    const { db } = await connectToMongo();
    const report = {
      name,
      email,
      description,
      createdAt: new Date()
    };
    await db.collection('reports').insertOne(report);

    await transporter.sendMail({
      from: 'ms462974@gmail.com',
      to: email,
      subject: 'Confirmación de reporte',
      text: `Hola ${name},\n\nHemos recibido tu reporte:\n"${description}"\n\nGracias por contactarnos.`,
    });

    res.status(200).json({ message: 'Reporte enviado y correo de confirmación enviado' });
  } catch (error) {
    console.error('Error al enviar el reporte:', error);
    res.status(500).json({ error: 'Error al procesar el reporte' });
  }
});

// Verify MFA route
app.post('/api/verify-mfa', async (req, res) => {
  const { correo, code } = req.body;

  try {
    const { db } = await connectToMongo();
    const user = await db.collection('users').findOne({ correo });
    if (!user || !user.mfaSecret) {
      return res.status(400).json({ error: 'MFA no configurado o no disponible' });
    }

    const isValid = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token: code,
      window: 1,
    });

    if (!isValid) {
      return res.status(400).json({ error: 'Código MFA incorrecto' });
    }

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ message: 'Autenticación exitosa', token, userId: user._id });
  } catch (error) {
    res.status(500).json({ error: 'Error al verificar el código MFA' });
  }
});

// Carousel route
app.get('/api/carousel', async (req, res) => {
  try {
    const { db } = await connectToMongo();
    const slides = await db.collection('carousel').find().limit(3).toArray();
    const normalizedSlides = slides.map(slide => ({
      ...slide,
      imageUrl: slide.image
    }));
    res.status(200).json(normalizedSlides);
  } catch (error) {
    console.error('Error al obtener datos del carrusel:', error);
    res.status(500).json({ error: 'Error al obtener datos del carrusel' });
  }
});

// Articles route
app.get('/api/articles/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { db } = await connectToMongo();

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ message: 'ID no válido' });
    }

    const article = await db.collection('carousel').findOne({ 
      _id: new ObjectId(id) 
    });

    if (!article) {
      return res.status(404).json({ message: 'Documento no encontrado en carousel' });
    }

    article.imageUrl = article.image;
    res.json(article);
  } catch (error) {
    res.status(500).json({ message: 'Error al obtener el documento' });
  }
});

// Calendar routes
app.get('/api/calendar', async (req, res) => {
  try {
    const { db } = await connectToMongo();
    const events = await db.collection('calendar').find().toArray();
    const normalizedEvents = events.map(event => ({
      ...event,
      imageUrl: event.imageUrl || '',
    }));
    res.json(normalizedEvents);
  } catch (error) {
    console.error('Error al obtener los eventos:', error);
    res.status(500).json({ message: 'Error al obtener los eventos' });
  }
});

// Calendar by ID route
app.get('/api/calendar/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { db } = await connectToMongo();

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ message: 'ID no válido' });
    }

    const event = await db.collection('calendar').findOne({ _id: new ObjectId(id) });
    if (!event) {
      return res.status(404).json({ message: 'Evento no encontrado' });
    }

    event.imageUrl = event.imageUrl || '';
    res.json(event);
  } catch (error) {
    console.error('Error al obtener el evento:', error);
    res.status(500).json({ message: 'Error al obtener el evento' });
  }
});

// User route
app.get('/api/user/:userId', async (req, res) => {
  let { userId } = req.params;

  try {
    const { db } = await connectToMongo();
    if (!ObjectId.isValid(userId)) {
      return res.status(400).json({ error: 'ID de usuario no válido' });
    }

    const user = await db.collection('users').findOne({ _id: new ObjectId(userId) });
    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    res.json(user);
  } catch (error) {
    console.error('Error al obtener datos del usuario:', error);
    res.status(500).json({ error: 'Error al obtener datos del usuario' });
  }
});

// Update user route
app.put('/api/user/:userId', async (req, res) => {
  const { userId } = req.params;
  const { nombre, descripcion } = req.body;

  try {
    const { db } = await connectToMongo();
    if (!ObjectId.isValid(userId)) {
      return res.status(400).json({ error: 'ID de usuario no válido' });
    }

    const user = await db.collection('users').findOne({ _id: new ObjectId(userId) });
    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    if (user.nombre === nombre && user.descripcion === descripcion) {
      return res.status(400).json({ error: 'No se realizaron cambios' });
    }

    const result = await db.collection('users').updateOne(
      { _id: new ObjectId(userId) },
      { $set: { nombre, descripcion } }
    );

    if (result.modifiedCount === 0) {
      return res.status(400).json({ error: 'No se realizaron cambios' });
    }

    res.status(200).json({ message: 'Perfil actualizado con éxito' });
  } catch (error) {
    console.error('Error al actualizar el perfil:', error);
    res.status(500).json({ error: 'Error al actualizar el perfil' });
  }
});

// News routes
app.get('/api/news', async (req, res) => {
  try {
    const { db } = await connectToMongo();
    const newsList = await db.collection('news').find().toArray();
    res.status(200).json(newsList);
  } catch (error) {
    console.error('Error al obtener las noticias:', error);
    res.status(500).json({ error: 'Error al obtener las noticias' });
  }
});

app.get('/api/news/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { db } = await connectToMongo();

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ message: 'ID no válido' });
    }

    const newsItem = await db.collection('news').findOne({ _id: new ObjectId(id) });
    if (!newsItem) {
      return res.status(404).json({ message: 'Noticia no encontrada' });
    }

    res.json(newsItem);
  } catch (error) {
    console.error('Error al obtener la noticia:', error);
    res.status(500).json({ message: 'Error al obtener la noticia' });
  }
});

// Rate article route
app.put('/api/articles/:id/rate', async (req, res) => {
  try {
    const { id } = req.params;
    const { rate } = req.body;
    const { db } = await connectToMongo();

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'ID no válido' });
    }

    if (rate < 1 || rate > 5) {
      return res.status(400).json({ error: 'La calificación debe estar entre 1 y 5' });
    }

    const result = await db.collection('carousel').updateOne(
      { _id: new ObjectId(id) },
      { $set: { rate } }
    );

    if (result.modifiedCount === 0) {
      return res.status(404).json({ error: 'Artículo no encontrado' });
    }

    res.json({ message: 'Calificación actualizada correctamente' });
  } catch (error) {
    console.error('Error al actualizar la calificación:', error);
    res.status(500).json({ error: 'Error al actualizar la calificación' });
  }
});

// Comment routes
app.post('/api/articles/:id/comment', async (req, res) => {
  try {
    const { id } = req.params;
    const { userId, comment } = req.body;
    const { db } = await connectToMongo();

    if (!ObjectId.isValid(id) || !ObjectId.isValid(userId)) {
      return res.status(400).json({ error: 'ID no válido' });
    }

    if (!comment.trim()) {
      return res.status(400).json({ error: 'El comentario no puede estar vacío' });
    }

    const user = await db.collection('users').findOne({ _id: new ObjectId(userId) });
    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    const newComment = {
      _id: new ObjectId(),
      userId: new ObjectId(userId),
      userName: user.nombre,
      comment,
      createdAt: new Date()
    };

    await db.collection('carousel').updateOne(
      { _id: new ObjectId(id) },
      { $push: { comments: newComment } }
    );

    res.status(201).json({ message: 'Comentario agregado correctamente' });
  } catch (error) {
    console.error('Error al agregar el comentario:', error);
    res.status(500).json({ error: 'Error al agregar el comentario' });
  }
});

app.get('/api/articles/:id/comments', async (req, res) => {
  try {
    const { id } = req.params;
    const { db } = await connectToMongo();

    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ error: 'ID de artículo no válido' });
    }

    const article = await db.collection('carousel').findOne({ _id: new ObjectId(id) });
    if (!article) {
      return res.status(404).json({ error: 'Artículo no encontrado' });
    }

    res.json(article.comments || []);
  } catch (error) {
    console.error('Error al obtener los comentarios:', error);
    res.status(500).json({ error: 'Error al obtener los comentarios' });
  }
});

app.put('/api/comments/:commentId', async (req, res) => {
  try {
    const { commentId } = req.params;
    const { userId, comment } = req.body;
    const { db } = await connectToMongo();

    if (!ObjectId.isValid(commentId) || !ObjectId.isValid(userId)) {
      return res.status(400).json({ error: 'ID no válido' });
    }

    if (!comment.trim()) {
      return res.status(400).json({ error: 'El comentario no puede estar vacío' });
    }

    const article = await db.collection('carousel').findOne({ 'comments._id': new ObjectId(commentId) });
    if (!article) {
      return res.status(404).json({ error: 'Comentario no encontrado' });
    }

    const commentToUpdate = article.comments.find(c => c._id.toString() === commentId);
    if (commentToUpdate.userId.toString() !== userId) {
      return res.status(403).json({ error: 'No tienes permiso para editar este comentario' });
    }

    await db.collection('carousel').updateOne(
      { _id: new ObjectId(article._id) },
      { $set: { 'comments.$[elem].comment': comment, 'comments.$[elem].updatedAt': new Date() } },
      { arrayFilters: [{ 'elem._id': new ObjectId(commentId) }] }
    );

    res.json({ message: 'Comentario actualizado correctamente' });
  } catch (error) {
    console.error('Error al editar el comentario:', error);
    res.status(500).json({ error: 'Error al editar el comentario' });
  }
});

app.delete('/api/comments/:commentId', async (req, res) => {
  try {
    const { commentId } = req.params;
    const { userId } = req.body;
    const { db } = await connectToMongo();

    if (!ObjectId.isValid(commentId) || !ObjectId.isValid(userId)) {
      return res.status(400).json({ error: 'ID no válido' });
    }

    const article = await db.collection('carousel').findOne({ 'comments._id': new ObjectId(commentId) });
    if (!article) {
      return res.status(404).json({ error: 'Comentario no encontrado' });
    }

    const commentToDelete = article.comments.find(c => c._id.toString() === commentId);
    if (commentToDelete.userId.toString() !== userId) {
      return res.status(403).json({ error: 'No tienes permiso para eliminar este comentario' });
    }

    await db.collection('carousel').updateOne(
      { _id: new ObjectId(article._id) },
      { $pull: { comments: { _id: new ObjectId(commentId) } } }
    );

    res.json({ message: 'Comentario eliminado correctamente' });
  } catch (error) {
    console.error('Error al eliminar el comentario:', error);
    res.status(500).json({ error: 'Error al eliminar el comentario' });
  }
});

// Create an SSE endpoint
app.get('/api/stream', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');

  const sendEvent = (data) => {
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  sendEvent({ message: 'Conexión establecida' });

  const interval = setInterval(() => {
    sendEvent({ timestamp: new Date().toISOString() });
  }, 5000);

  req.on('close', () => {
    clearInterval(interval);
  });
});

// Export a serverless function handler for Vercel
export default app;