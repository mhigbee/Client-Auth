/* eslint-disable import/no-extraneous-dependencies */
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const express = require('express');
const session = require('express-session');
const cors = require('cors');

const User = require('./user.js');

const STATUS_USER_ERROR = 422;
const BCRYPT_COST = 11;

const server = express();
// to enable parsing of json bodies for post requests
server.use(bodyParser.json());
server.use(session({
  secret: 'e5SPiqsEtjexkTj3Xqovsjzq8ovjfgVDFMfUzSmJO21dtXs4re',
  resave: true,
  saveUninitialized: false
}));

// Uncomment when using this server for the client-auth sprint
// const corsOptions = {
//    "origin": "http://localhost:3000",
//    "credentials": true
// };

// server.use(cors(corsOptions));

/* Sends the given err, a string or an object, to the client. Sets the status
 * code appropriately. */
const sendUserError = (err, res) => {
  res.status(STATUS_USER_ERROR);
  if (err && err.message) {
    res.json({ message: err.message, stack: err.stack });
  } else {
    res.json({ error: err });
  }
};

server.post('/users', (req, res) => {
  const { username, password } = req.body;
  // We don't need to check username because it'll be handled by mongoose
  // validation while saving the user. An empty password, by contrast, can still
  // be successfully hashed, so we must explicitly check for emptiness here and
  // respond with an error.
  if (!password) {
    sendUserError('Must provide password', res);
    return;
  }

  bcrypt.hash(password, BCRYPT_COST, (err, hash) => {
    if (err) {
      sendUserError("Couldn't hash password", res);
      return;
    }

    const user = new User({ username, passwordHash: hash });
    user.save((saveErr) => {
      if (saveErr) {
        sendUserError(saveErr, res);
        return;
      }

      res.json(user);
    });
  });
});

server.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username) {
    sendUserError('Must provide username', res);
    return;
  }
  if (!password) {
    sendUserError('Must provide password', res);
    return;
  }

  User.findOne({ username }, (err, user) => {
    if (err) {
      sendUserError(err, res);
      return;
    }
    if (!user) {
      sendUserError('Bad credentials', res);
      return;
    }

    bcrypt.compare(password, user.passwordHash, (compareErr, valid) => {
      if (compareErr) {
        sendUserError(compareErr, res);
        return;
      }
      if (!valid) {
        sendUserError('Bad credentials', res);
        return;
      }

      req.session.username = user.username;
      res.json({ success: true });
    });
  });
});

server.post('/logout', (req, res) => {
  if (!req.session.username) {
    sendUserError('Must be logged in', res);
    return;
  }

  req.session.username = null;
  res.json({ success: true });
});

const ensureLoggedIn = (req, res, next) => {
  const { username } = req.session;
  if (!username) {
    sendUserError('Must be logged in', res);
    return;
  }

  User.findOne({ username }, (err, user) => {
    if (err) {
      sendUserError(err, res);
    } else if (!user) {
      sendUserError('Must be logged in', res);
    } else {
      req.user = user;
      next();
    }
  });
};

server.get('/me', ensureLoggedIn, (req, res) => {
  // Do NOT modify this route handler in any way.
  res.json(req.user);
});

const checkRestricted = ((req, res, next) => {
  const path = req.path;
  if (/restricted/.test(path)) {
    if (!req.session.username) {
      sendUserError('Must be logged in to access a restricted path', res);
      return;
    }
  }
  next();
});

server.use(checkRestricted);

server.get('/restricted/users', (req, res) => {
  User.find({})
    .exec()
    .then((users) => {
      res.json(users);
    })
    .catch((err) => {
      sendUserError(err, res);
      return;
    });
});

module.exports = { server };

