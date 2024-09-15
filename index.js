import * as dotenv from 'dotenv';
dotenv.config(); // Загружаем переменные окружения из файла .env

import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

const app = express();
app.use(express.json());

const jwtSecret = process.env.JWT_SECRET; // Используем секретный ключ для JWT из .env

// Middleware для проверки токена JWT
function authJWT(req, res, next) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        const token = authHeader.substring(7); // Извлекаем сам токен
        jwt.verify(token, jwtSecret, (err, user) => {
            if (err) {
                return res.status(403).send('Неправильный или истекший токен');
            }
            req.user = user;
            next();
        });
    } else {
        return res.status(401).send('Неавторизованный пользователь: нет токена');
    }
}

// Middleware для проверки роли пользователя
function authRole(role) {
    return (req, res, next) => {
        if (req.user.role === role) {
            next();
        } else {
            return res.status(403).send('Нет доступа');
        }
    };
}

// Симуляция базы данных пользователей
const users = [
    { id: '1', email: 'jack@sparrow.com', password: await bcrypt.hash('1234qwerty', 10), role: 'simpleUser' },
    { id: '007', email: 'bond@james.com', password: await bcrypt.hash('1234qwerty', 10), role: 'Admin' }
];

// Маршрут для логина и генерации токена JWT
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const user = users.find(u => u.email === email);
    if (!user) {
        return res.status(404).send('Пользователь не найден');
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        return res.status(401).send('Пароль неверный');
    }

    const token = jwt.sign(
        { userId: user.id, email: user.email, role: user.role },
        jwtSecret,
        { expiresIn: '1h' }
    );

    res.json({ token });
});

// Защищенный маршрут
app.get('/protected', authJWT, (req, res) => {
    res.json({ message: 'Доступ к защищенному маршруту', user: req.user });
});

// Маршрут для администраторов
app.get('/admin', authJWT, authRole('Admin'), (req, res) => {
    res.send('Добро пожаловать, администратор');
});

// Запуск сервера
app.listen(3000, () => {
    console.log('Сервер запущен на http://localhost:3000');
});
