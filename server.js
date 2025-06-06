const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');

const app = express();
const db = new sqlite3.Database('./database.db');
const verificationCodes = new Map(); // Armazena códigos temporariamente

// Configuração do servidor
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static('public'));

// Criar tabela de usuários com novos campos
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      nome TEXT,
      cpf TEXT,
      nascimento TEXT,
      email TEXT UNIQUE,
      password TEXT
    )
  `);
});

// Configurar transporte de e-mail
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'phprogramadorsoftware@gmail.com',
    pass: 'xedznghkfriutjsx' // Sua senha de aplicativo gerada no Google
  }
});

// Página inicial (login)
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Cadastro
app.post('/register', (req, res) => {
  const { nome, cpf, nascimento, email, password } = req.body;

  // Verifica idade
  const birthDate = new Date(nascimento);
  const today = new Date();
  const age = today.getFullYear() - birthDate.getFullYear();
  if (age < 13 || (age === 13 && today < new Date(today.getFullYear(), birthDate.getMonth(), birthDate.getDate()))) {
    return res.send('Você precisa ter 13 anos ou mais para criar uma conta.');
  }

  // Verifica se o email já está cadastrado
  db.get('SELECT email FROM users WHERE email = ?', [email], async (err, row) => {
    if (err) return res.send('Erro no banco de dados: ' + err.message);
    if (row) return res.send('Este email já está cadastrado.');

    // Gera código de verificação
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    verificationCodes.set(email, code);

    // Envia e-mail com o código
    try {
      await transporter.sendMail({
        from: 'phprogramadorsoftware@gmail.com',
        to: email,
        subject: 'Código de verificação',
        text: `Seu código de verificação é: ${code}`
      });
    } catch (err) {
      return res.send('Erro ao enviar e-mail de verificação: ' + err.message);
    }

    // Criptografa senha
    const hashedPassword = await bcrypt.hash(password, 10);

    // Salva usuário no banco
    db.run(
      `INSERT INTO users (nome, cpf, nascimento, email, password) VALUES (?, ?, ?, ?, ?)`,
      [nome, cpf, nascimento, email, hashedPassword],
      function (err) {
        if (err) return res.send('Erro ao cadastrar: ' + err.message);
        res.redirect('/verify.html');
      }
    );
  });
});

// Verificação de e-mail
app.post('/verify', (req, res) => {
  const { email, code } = req.body;

  const storedCode = verificationCodes.get(email);
  if (storedCode && storedCode === code) {
    verificationCodes.delete(email);
    return res.redirect('/home.html'); // Usuário verificado, vai para home
  }

  res.send('Código inválido ou expirado. <a href="/verify.html">Tentar novamente</a>');
});

// Login
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err) return res.send('Erro no login');
    if (!user) return res.send('Usuário não encontrado');

    const valid = await bcrypt.compare(password, user.password);
    if (valid) {
      res.redirect('/home.html');
    } else {
      res.send('Senha incorreta. <a href="/">Tentar novamente</a>');
    }
  });
});

// Redefinir senha (iremos implementar mais tarde com código de verificação)
app.post('/reset', (req, res) => {
  const { email, newPassword } = req.body;
  bcrypt.hash(newPassword, 10, (err, hashedPassword) => {
    if (err) return res.send('Erro ao redefinir senha: ' + err.message);
    db.run('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email], function (err) {
      if (this.changes > 0) {
        res.send('Senha redefinida com sucesso. <a href="/">Fazer login</a>');
      } else {
        res.send('Email não encontrado. <a href="/reset.html">Tentar novamente</a>');
      }
    });
  });
});

// Mapa para armazenar os códigos de redefinição
const resetCodes = new Map();

// Envia o código de redefinição
app.post('/send-reset-code', async (req, res) => {
  const { email } = req.body;

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (err || !user) return res.send('E-mail não encontrado');

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    resetCodes.set(email, code);

    try {
      await transporter.sendMail({
        from: 'phprogramadorsoftware@gmail.com',
        to: email,
        subject: 'Código para redefinir sua senha',
        text: `Seu código de redefinição de senha é: ${code}`
      });
      res.redirect('/confirm-reset.html');
    } catch (error) {
      res.send('Erro ao enviar código: ' + error.message);
    }
  });
});

// Confirma o código e redefine a senha
app.post('/confirm-reset', async (req, res) => {
  const { email, code, newPassword } = req.body;

  if (resetCodes.get(email) !== code) {
    return res.send('Código inválido ou expirado. <a href="/reset.html">Tentar novamente</a>');
  }

  const hashedPassword = await bcrypt.hash(newPassword, 10);

  db.run('UPDATE users SET password = ? WHERE email = ?', [hashedPassword, email], function (err) {
    if (err) return res.send('Erro ao redefinir senha: ' + err.message);
    resetCodes.delete(email);
    res.send('Senha redefinida com sucesso. <a href="/">Fazer login</a>');
  });
});

// Iniciar servidor
app.listen(3000, () => {
  console.log('Servidor rodando em http://localhost:3000');
});