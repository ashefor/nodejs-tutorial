const path = require('path');
const fs = require('fs')

const MONGODB_URI = `mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASSWORD}@cluster0.sj1otro.mongodb.net/${process.env.MONGO_DEFAULT_DATABASE}`;

const express = require('express');
const helmet = require('helmet');
const compression = require('compression');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoDBStore  = require('connect-mongodb-session')(session);
const csrf = require('csurf');
const flash = require('connect-flash');
const multer = require('multer');

const diskStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'images');
  },
  filename: function (req, file, cb) {
    cb(null, new Date().toISOString() + file.originalname);
  }
})

const fileFilter = (req, file, cb) => {
  if (
    file.mimetype === 'image/png' ||
    file.mimetype === 'image/jpg' ||
    file.mimetype === 'image/jpeg'
  ) {
    cb(null, true);
  } else {
    cb(null, false);
  }
}

const errorController = require('./controllers/error');
const User = require('./models/user');
const store = new MongoDBStore({
  uri: MONGODB_URI,
  collection: 'sessions'
})

const app = express();

app.set('view engine', 'ejs');
app.set('views', 'views');

const adminRoutes = require('./routes/admin');
const shopRoutes = require('./routes/shop');
const authRoutes = require('./routes/auth');

const accessLogStream = fs.createWriteStream(path.join(__dirname, 'access.log'), { flags: 'a' });

const scriptSources = ["'self'", "'unsafe-inline'", 'https://js.paystack.co/v1/inline.js']
 
// app.use(helmet.contentSecurityPolicy({
//   useDefaults: true,
//   directives: {
//     scriptSrc: scriptSources,
//     "default-src": ["'self'", "https://js.paystack.co/v1/inline.js"],
//     "frame-src": ["'self'", "https://js.paystack.co/v1/inline.js"]
//   }
// }))
app.use(compression())
// app.use(morgan('combined', {stream: accessLogStream}));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(multer({storage: diskStorage, fileFilter: fileFilter}).single('image'));
app.use(express.static(path.join(__dirname, 'public')));
app.use('/images' ,express.static(path.join(__dirname, 'images')));
app.use(session({ secret: 'my secret', resave: false, saveUninitialized: false, store }));
app.use(csrf());
app.use(flash());

app.use((req, res, next) => {
  res.locals.isAuthenticated = req.session.isLoggedIn;
  res.locals.csrfToken = req.csrfToken();
  next();
})

app.use((req, res, next) => {
  if (!req.session.user) {
    return next();
  };
  User.findById(req.session.user._id)
    .then(user => {
      if (!user) {
        return next();
      }
      req.user = user;
      next();
    })
    .catch(err => {
      next(new Error(err));
    });
});


app.use('/admin', adminRoutes);
app.use(shopRoutes);
app.use(authRoutes);
app.use('/500', errorController.get500);
app.use(errorController.get404);

app.use((error, req, res, next) => {
  console.log(error);
  res.status(500).render('500', {
    pageTitle: 'Error',
    path: '/500',
    isAuthenticated: req.session.isLoggedIn
  });
})
mongoose
  .connect(
    MONGODB_URI
  )
  .then(result => {
    app.listen(process.env.PORT || 3001);
    console.log('Connected to Database');
  })
  .catch(err => {
    console.log(err);
  });
