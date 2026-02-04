const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const DiscordStrategy = require('discord-strategy').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const { findUserByGoogleId, createUserFromGoogle, findUserByDiscordId, createUserFromDiscord, findUserByGithubId, createUserFromGithub } = require('../models/User');

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL,
  passReqToCallback: true
}, async (req, accessToken, refreshToken, profile, done) => {
  try {
    const db = req.app.locals.db;
    let user = await findUserByGoogleId(db, profile.id);
    if (!user) {
      user = await createUserFromGoogle(db, {
        googleId: profile.id,
        email: profile.emails[0].value,
        name: profile.displayName,
        picture: profile.photos[0].value
      });
    }
    done(null, user);
  } catch (error) {
    done(error, null);
  }
}));

passport.use(new DiscordStrategy({
  clientID: process.env.DISCORD_CLIENT_ID,
  clientSecret: process.env.DISCORD_CLIENT_SECRET,
  callbackURL: process.env.DISCORD_CALLBACK_URL,
  scope: ['identify', 'email'],
  passReqToCallback: true
}, async (req, accessToken, refreshToken, profile, done) => {
  try {
    const db = req.app.locals.db;
    let user = await findUserByDiscordId(db, profile.id);
    if (!user) {
      user = await createUserFromDiscord(db, {
        discordId: profile.id,
        email: profile.email,
        username: profile.username,
        avatar: profile.avatar
      });
    }
    done(null, user);
  } catch (error) {
    done(error, null);
  }
}));

passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: process.env.GITHUB_CALLBACK_URL,
  scope: ['user:email'],
  passReqToCallback: true
}, async (req, accessToken, refreshToken, profile, done) => {
  try {
    const db = req.app.locals.db;
    let user = await findUserByGithubId(db, profile.id);
    if (!user) {
      user = await createUserFromGithub(db, {
        githubId: profile.id,
        email: profile.emails[0].value,
        username: profile.username,
        avatar: profile.photos[0].value
      });
    }
    done(null, user);
  } catch (error) {
    done(error, null);
  }
}));

// ⚠️ PAS de serializeUser/deserializeUser car on utilise JWT (stateless)
// Ces fonctions sont uniquement pour les sessions

module.exports = passport;
