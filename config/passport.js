var passport=require('passport');
var User=require('../models/user');
var LocalStrategy=require('passport-local').Strategy;

passport.serializeUser(function(user,done){
    done(null,user.id);
});

passport.deserializeUser(function(id,done){
    User.findById(id,function(err,user){
        done(err,user);
    });
});

passport.use('local.signup',new LocalStrategy({
    usernameField:'username',
    passwordField:'password',
    cnnoField:'cnno',
    emailIdField:'emailId',
    passReqToCallback: true
},function(req,username,password,cnno,emailId,done){
    req.checkBody('username','Enter username').notEmpty();
    req.checkBody('password','Invalid password').notEmpty().isLength({min:4});
    req.checkBody('cnno','Contact number length should be 10').notEmpty().isLength({min:10,max:10});
    req.checkBody('emailId','Invalid email').notEmpty().isEmail();
 
    var errors=req.validationErrors();
    if(errors){
        var messages=[];
        errors.forEach(function(error){
            messages.push(error.msg);
        });
        return done(null,false,req.flash('error',messages));
    }
    User.findOne({'emailId':emailId},function(err,user){
        if(err){
            return done(err);
        }
        if(user){
            return done(null,false,{message:'email is already exists'});
        }
        var  newUser=new User();
        newUser.emailId=emailId;
        newUser.password=newUser.encryptPassword(password);
        newUser.username=username;
        newUser.cnno=cnno;
        newUser.save(function(err,result){
            if(err){
                return done(err);
            }
            return done(null,newUser);
        });
    });
}));
