const express = require('express');
const passport = require('passport');
const session = require('express-session');
const jwt = require('jsonwebtoken');
const GithubStrategy = require('passport-github2');

require('dotenv').config();

const app = express();

app.use(
  session({
    secret: process.env.GITHUB_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

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
      clientSecret: process.env.GITHUB_SECRET,
      callbackURL: process.env.GITHUB_CALLBACK_URL,
    },
    (accessToken, refreshToken, profile, done) => {
      return done(null, profile);
    }
  )
);

app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }), (req, res) => {
  const redirectUrl = `${process.env.GITHUB_REDIRECT_URL}/success?user=${encodeURIComponent(JSON.stringify(req.user))}`;
  res.redirect(redirectUrl);
});

app.get('/auth/github/callback', passport.authenticate('github', { failureRedirect: '/login' }), (req, res) => {
  const { user } = req;

  const token = jwt.sign(user, process.env.JWT_SECRET);
  const redirectUrl = `${process.env.GITHUB_REDIRECT_URL}/success/${encodeURIComponent(token)}`;

  res.redirect(redirectUrl);
});

app.get('/success', (req, res) => {
  res.redirect(`${process.env.GITHUB_REDIRECT_URL}/`);
});

module.exports = app;
