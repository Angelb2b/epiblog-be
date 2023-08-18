const express = require('express');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GithubStrategy = require('passport-github2');

require('dotenv').config();

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

passport.use(
  new GithubStrategy(
    {
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: process.env.GITHUB_CALLBACK_URL,
    },
    (accessToken, refreshToken, profile, done) => {
      return done(null, { accessToken, profile });
    }
  )
);

app.get('/auth/github', passport.authenticate('github'));

app.get(
  '/auth/github/callback',
  passport.authenticate('github', { failureRedirect: '/login' }),
  (req, res) => {
    const { accessToken, profile } = req.user;

    const token = jwt.sign({ accessToken, profile }, process.env.JWT_SECRET);

    res.redirect(`${process.env.REDIRECT_URL}?token=${encodeURIComponent(token)}`);
  }
);

app.get('/protected', (req, res) => {
  const token = req.query.token;

  if (!token) {
    return res.status(401).json({ message: 'Token di accesso mancante' });
  }

  try {
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

    const { accessToken, profile } = decodedToken;

    res.json({ accessToken, profile });
  } catch (error) {
    res.status(403).json({ message: 'Token di accesso non valido o scaduto' });
  }
});

app.listen(3000, () => {
  console.log('Server avviato sulla porta 3000');
});
