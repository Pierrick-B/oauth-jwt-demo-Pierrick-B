const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { findUserByGoogleId, createUserFromGoogle } = require('../models/User');

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

// ⚠️ PAS de serializeUser/deserializeUser car on utilise JWT (stateless)
// Ces fonctions sont uniquement pour les sessions

module.exports = passport;
