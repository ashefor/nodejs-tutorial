const User = require('../models/user');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { validationResult } = require('express-validator');

const transporter = nodemailer.createTransport({
  host: "sandbox.smtp.mailtrap.io",
  port: 2525,
  auth: {
    user: "99ed50d2f24f48",
    pass: "a62676e7f0045b"
  }
})
exports.getLogin = (req, res, next) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0]
  } else {
    message = null
  }
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    errorMessage: message,
    oldInput: {
      email: '',
      password: '',
    },
    validationErrors: []
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).render('auth/login', {
      path: '/login',
      pageTitle: 'login',
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: email,
        password: password,
      },
      validationErrors: errors.array()
    })
  }
  User.findOne({ email: email }).then(user => {
    if (!user) {
      return res.status(422).render('auth/login', {
        path: '/login',
        pageTitle: 'login',
        errorMessage: 'Invalid email or password',
        oldInput: {
          email: email,
          password: password,
        },
        validationErrors: []
      })
    }
    bcrypt.compare(password, user.password).then((doMatch) => {
      if (doMatch) {
        req.session.isLoggedIn = true;
        req.session.user = user;
        return req.session.save((err) => {
          res.redirect('/');
        })
      }
      return res.status(422).render('auth/login', {
        path: '/login',
        pageTitle: 'login',
        errorMessage: 'Password not correct',
        oldInput: {
          email: email,
          password: password,
        },
        validationErrors: []
      })
    }).catch(err => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    })
  })
};

exports.getSignup = (req, res, next) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0]
  } else {
    message = null
  }
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    errorMessage: message,
    oldInput: {
      email: '',
      password: '',
      confirmPassword: ''
    },
    validationErrors: []
  });
}

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    console.log(errors.array())
    return res.status(422).render('auth/signup', {
      path: '/signup',
      pageTitle: 'Signup',
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: email,
        password: password,
        confirmPassword: req.body.confirmPassword
      },
      validationErrors: errors.array()
    })
  }
  bcrypt.hash(password, 12).then((hasedPassword) => {
    const user = new User({
      email: email,
      password: hasedPassword,
      cart: { items: [] }
    })
    return user.save();
  })
    .then(() => {
      res.redirect('/login')
      return transporter.sendMail({
        from: 'asheformichael@gmail.com',
        to: email,
        subject: 'Signup succeeded!',
        html: '<h1>You successfully signed up!</h1>'
      }).catch((err) => {
        const error = new Error(err);
        error.httpStatusCode = 500;
        return next(error);
      })
    })
}

exports.postLogout = (req, res, next) => {
  req.session.destroy((err) => {
    console.log(err)
    res.redirect('/');
  })
};

exports.getReset = (req, res, next) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0]
  } else {
    message = null
  }
  res.render('auth/reset', {
    path: '/reset',
    pageTitle: 'Reset Password',
    errorMessage: message
  });
}

exports.postReset = (req, res, next) => {
  crypto.randomBytes(32, (err, buffer) => {
    if (err) {
      console.log(err);
      return res.redirect('/reset');
    }
    const token = buffer.toString('hex');
    User.findOne({ email: req.body.email }).then(user => {
      if (!user) {
        req.flash('error', 'No account with that email found');
        return res.redirect('/reset');
      }
      user.resetToken = token;
      user.resetTokenExpiration = Date.now() + 3600000;
      return user.save().then(() => {
        res.redirect('/');
        transporter.sendMail({
          from: 'asheformichael@gmail.com',
          to: req.body.email,
          subject: 'Password reset',
          html: `
          <p>You requested a password reset</p>
          <p>Click this <a href="http://localhost:3000/reset/${token}">link</a> to set a new password</p>
        `
        }).catch((err) => {
          const error = new Error(err);
          error.httpStatusCode = 500;
          return next(error);
        })
      });
    }).catch((err) => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    })
  })
}

exports.getNewPassword = (req, res, next) => {
  const token = req.params.token;
  User.findOne({ resetToken: token, resetTokenExpiration: { $gt: Date.now() } }).then(user => {

    let message = req.flash('error');
    if (message.length > 0) {
      message = message[0]
    } else {
      message = null
    }
    res.render('auth/new-password', {
      path: '/new-password',
      pageTitle: 'New Password',
      errorMessage: message,
      userId: user._id.toString(),
      passwordToken: token
    });
  })
}

exports.postNewPassword = (req, res, next) => {
  const newPassword = req.body.password;
  const userId = req.body.userId;
  const passwordToken = req.body.passwordToken;
  let userResult;
  User.findOne(
    {
      resetToken: passwordToken,
      resetTokenExpiration: { $gt: Date.now() },
      _id: userId
    }).then(user => {
      userResult = user
      return bcrypt.hash(newPassword, 12).then(hashedPassword => {
        user.password = hashedPassword;
        user.resetToken = undefined;
        user.resetTokenExpiration = undefined;
        return user.save();
      }).then(() => {
        res.redirect('/login');
        return transporter.sendMail({
          from: 'asheformichael@gmail.com',
          to: userResult.email,
          subject: 'Password reset successful',
          html: '<h1>You successfully reset your password!</h1>'
        })
      }).catch(err => {
        const error = new Error(err);
        error.httpStatusCode = 500;
        return next(error);
      })
    }).catch(err => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    })
}
