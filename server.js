const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseAnonKey);

// Middleware para validar el Token JWT de Supabase
const authenticateUser = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Acceso no autorizado. Token faltante.' });
    }
    const token = authHeader.split(' ')[1];
    const { data: { user }, error } = await supabase.auth.getUser(token);

    if (error || !user) {
        return res.status(401).json({ error: 'Token inválido o sesión expirada.' });
    }

    req.user = user;
    req.token = token;
    next();
};

// ==========================================
// RUTAS DE AUTENTICACIÓN
// ==========================================

// Registrar usuario
app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    const { data, error } = await supabase.auth.signUp({ email, password });
    if (error) return res.status(400).json({ error: error.message });
    res.json({ message: 'Usuario registrado. Verifique su correo electrónico.', user: data.user, session: data.session });
});

// Iniciar sesión
app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) return res.status(400).json({ error: error.message });
    res.json({ user: data.user, session: data.session });
});

// Solicitar correo de recuperación de contraseña
app.post('/api/auth/recover', async (req, res) => {
    const { email } = req.body;
    const { error } = await supabase.auth.resetPasswordForEmail(email, {
        redirectTo: process.env.FRONTEND_URL || 'http://localhost:5500'
    });
    if (error) return res.status(400).json({ error: error.message });
    res.json({ message: 'Se ha enviado un enlace de recuperación a tu correo.' });
});

// Restablecer contraseña con el token de recuperación
app.post('/api/auth/reset-password', authenticateUser, async (req, res) => {
    const { newPassword } = req.body;
    const userClient = createClient(supabaseUrl, supabaseAnonKey, {
        global: { headers: { Authorization: `Bearer ${req.token}` } }
    });
    const { error } = await userClient.auth.updateUser({ password: newPassword });
    if (error) return res.status(400).json({ error: error.message });
    res.json({ message: 'Contraseña actualizada correctamente.' });
});

// ==========================================
// RUTAS DE NOTAS (PROTEGIDAS)
// ==========================================

// Obtener todas las notas del usuario autenticado
app.get('/api/notes', authenticateUser, async (req, res) => {
    const userClient = createClient(supabaseUrl, supabaseAnonKey, {
        global: { headers: { Authorization: `Bearer ${req.token}` } }
    });
    const { data, error } = await userClient.from('notes').select('*').order('created_at', { ascending: false });
    if (error) return res.status(400).json({ error: error.message });
    res.json(data);
});

// Crear una nueva nota
app.post('/api/notes', authenticateUser, async (req, res) => {
    const { title, content, category, color, pinned } = req.body;
    const userClient = createClient(supabaseUrl, supabaseAnonKey, {
        global: { headers: { Authorization: `Bearer ${req.token}` } }
    });
    const { data, error } = await userClient.from('notes').insert([{
        user_id: req.user.id,
        title: title || 'Sin título',
        content: content || '',
        category: category || 'General',
        color: color || 'slate',
        pinned: !!pinned,
        updated_at: new Date().toISOString()
    }]).select();

    if (error) return res.status(400).json({ error: error.message });
    res.json(data[0]);
});

// Actualizar nota
app.put('/api/notes/:id', authenticateUser, async (req, res) => {
    const { id } = req.params;
    const { title, content, category, color, pinned } = req.body;
    const userClient = createClient(supabaseUrl, supabaseAnonKey, {
        global: { headers: { Authorization: `Bearer ${req.token}` } }
    });

    const { data, error } = await userClient.from('notes').update({
        title,
        content,
        category,
        color,
        pinned,
        updated_at: new Date().toISOString()
    }).eq('id', id).select();

    if (error) return res.status(400).json({ error: error.message });
    res.json(data[0]);
});

// Eliminar nota
app.delete('/api/notes/:id', authenticateUser, async (req, res) => {
    const { id } = req.params;
    const userClient = createClient(supabaseUrl, supabaseAnonKey, {
        global: { headers: { Authorization: `Bearer ${req.token}` } }
    });

    const { error } = await userClient.from('notes').delete().eq('id', id);
    if (error) return res.status(400).json({ error: error.message });
    res.json({ message: 'Nota eliminada correctamente' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor iniciado en el puerto ${PORT}`));
