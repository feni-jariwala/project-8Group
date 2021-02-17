var express = require('express');
var router = express.Router();
var csrf=require('csurf');
var passport=require('passport');

var csrfProtection=csrf();
router.use(csrfProtection);
/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});

router.get('/user/signup',function(req,res,next){
  res.render('user/signup',{csrfToken: req.csrfToken()});
});
router.post('/user/signup',passport.authenticate('local.signup',{
  successRedirect: '/user/profile',
  failureRedirect: '/user/signup',
  failureFlash: true
}));
router.get('/user/profile',function(req,res,next){
  res.render('user/profile');
});

module.exports = router;
