const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();

const jwtSecret = 'mysecret';

const register = async (req, res) => {
  const { username, password } = req.body;

  try {
    const createdUser = await prisma.user.create({
      data: {
        username,
        password: await bcrypt.hash(password, 10)
      },
    });
    res.json({ data: createdUser });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
};

const login = async (req, res) => {
  const { username, password } = req.body;
  const userFound = await prisma.user.findFirst({
    where: {
      username,
    },
  });

  const passwordValid = await bcrypt.compare(password, userFound.password);
  if (!userFound || !passwordValid) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  const token = jwt.sign({ username }, jwtSecret);
  res.json({ token: token, username: username });
};

module.exports = {
  register,
  login,
};