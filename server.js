const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Low } = require('lowdb');
const { JSONFile } = require('lowdb/node');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-me';

// ---------- 初始化数据库 ----------
const file = path.join(__dirname, 'db.json');
const adapter = new JSONFile(file);
const db = new Low(adapter);

// ---------- 启动函数（所有 await 都在 async 函数内部） ----------
(async () => {
  // 读取数据库
  await db.read();
  db.data ||= { users: [], teachers: [] };

  app.use(cors());
  app.use(express.json());

  // ---------- 中间件：验证 Token ----------
  function auth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: '未登录' });
    const token = authHeader.split(' ')[1];
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      req.userId = decoded.userId;
      next();
    } catch {
      res.status(401).json({ error: '无效 token' });
    }
  }

  // ---------- 注册 ----------
  app.post('/api/register', async (req, res) => {
    const { name, phone, password, role } = req.body;
    if (!name || !phone || !password || !role) return res.status(400).json({ error: '信息不完整' });
    const exist = db.data.users.find(u => u.phone === phone);
    if (exist) return res.status(400).json({ error: '手机号已注册' });
    const hashed = bcrypt.hashSync(password, 10);
    const user = { id: Date.now().toString(), name, phone, password: hashed, role };
    db.data.users.push(user);
    await db.write();
    const token = jwt.sign({ userId: user.id }, JWT_SECRET);
    res.json({ token, user: { id: user.id, name: user.name, phone: user.phone, role: user.role } });
  });

  // ---------- 登录 ----------
  app.post('/api/login', async (req, res) => {
    const { phone, password } = req.body;
    const user = db.data.users.find(u => u.phone === phone);
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: '手机号或密码错误' });
    }
    const token = jwt.sign({ userId: user.id }, JWT_SECRET);
    res.json({ token, user: { id: user.id, name: user.name, phone: user.phone, role: user.role } });
  });

  // ---------- 获取老师列表（支持筛选） ----------
  app.get('/api/teachers', (req, res) => {
    let list = db.data.teachers;
    const { subject, grade, priceMax } = req.query;
    if (subject) list = list.filter(t => t.subject === subject);
    if (grade) list = list.filter(t => t.grade === grade);
    if (priceMax) list = list.filter(t => t.price <= parseInt(priceMax));
    res.json({ teachers: list });
  });

  // ---------- 获取单个老师 ----------
  app.get('/api/teachers/:id', (req, res) => {
    const teacher = db.data.teachers.find(t => t.id === req.params.id);
    if (!teacher) return res.status(404).json({ error: '未找到' });
    res.json({ teacher });
  });

  // ---------- 发布老师（需登录） ----------
  app.post('/api/teachers', auth, async (req, res) => {
    const { name, subject, grade, price, location, desc, phone } = req.body;
    if (!name || !subject || !grade || !price || !phone) {
      return res.status(400).json({ error: '必填项缺失' });
    }
    const newTeacher = {
      id: 't' + Date.now(),
      userId: req.userId,
      name,
      subject,
      grade,
      price: parseInt(price),
      location: location || '',
      desc: desc || '',
      phone,
      createdAt: Date.now()
    };
    db.data.teachers.push(newTeacher);
    await db.write();
    res.json({ teacher: newTeacher });
  });

  // ---------- 删除老师（仅自己） ----------
  app.delete('/api/teachers/:id', auth, async (req, res) => {
    const idx = db.data.teachers.findIndex(t => t.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: '不存在' });
    if (db.data.teachers[idx].userId !== req.userId) {
      return res.status(403).json({ error: '无权限删除' });
    }
    db.data.teachers.splice(idx, 1);
    await db.write();
    res.json({ success: true });
  });

  // ---------- 启动 ----------
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 服务已启动，端口 ${PORT}`);
  });
})();