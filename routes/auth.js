const express = require('express');
const User = require('../models/user');

const authController = require('../controllers/auth');
const { check, body } = require('express-validator');

const router = express.Router();

router.get('/login', authController.getLogin);

router.post('/login', [
    body('email').isEmail().normalizeEmail(),
    body('password', 'Please enter a password with only numbers and text and at least 5 characters').trim().isLength({ min: 5 }).isAlphanumeric(),
], authController.postLogin);

router.get('/signup', authController.getSignup);

router.post('/signup', [
    check('email').isEmail().normalizeEmail().withMessage('Please enter a valid email address').custom((value, { req }) => {
        return User.findOne({ email: value }).then((userDoc) => {
            if (userDoc) {
                return Promise.reject('User already exists');
            }
        })
    }),
    body('password', 'Please enter a password with only numbers and text and at least 5 characters').trim().isLength({ min: 5 }).isAlphanumeric(),
    body('confirmPassword').trim().custom((value, { req }) => {
        if (value !== req.body.password) {
            throw new Error('Passwords do not match');
        }
        return true
    })
], authController.postSignup);

router.post('/logout', authController.postLogout);

router.get('/reset', authController.getReset);

router.post('/reset', authController.postReset);

router.get('/reset/:token', authController.getNewPassword);

router.post('/new-password', authController.postNewPassword);

module.exports = router;