const path = require('path');

const express = require('express');

const adminController = require('../controllers/admin');

const isAuth = require('../middlewares/is-auth');
const { body } = require('express-validator');

const router = express.Router();

// /admin/add-product => GET
router.get('/add-product',isAuth, adminController.getAddProduct);

// /admin/products => GET
router.get('/products',isAuth, adminController.getProducts);

// /admin/add-product => POST
router.post('/add-product', [
    body('title').isString().isLength({ min: 3 }).trim().withMessage('Title must be at least 3 characters long'),
    // body('imageUrl', 'Please enter a valid URL').isURL(),
    body('price').isFloat(),
    body('description').isLength({ min: 5, max: 200 }).trim().withMessage('Description must be at least 3 characters and not more than 200 characters'),
], isAuth, adminController.postAddProduct);

router.get('/edit-product/:productId',isAuth, adminController.getEditProduct);

router.post('/edit-product', [
    body('title').isString().isLength({ min: 3 }).trim().withMessage('Title must be at least 3 characters long'),
    // body('imageUrl', 'Please enter a valid URL').isURL(),
    body('price').isFloat(),
    body('description').isLength({ min: 5, max: 200 }).trim().withMessage('Description must be at least 3 characters and not more than 200 characters'),
], isAuth, adminController.postEditProduct);

router.delete('/products/:productId', isAuth, adminController.deleteProduct);

module.exports = router;
