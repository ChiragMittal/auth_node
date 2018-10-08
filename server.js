var express = require('express');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var flash = require('connect-flash');
var session = require('express-session');
var expressValidator = require('express-validator');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var mongo = require('mongodb');
var mongoose = require('mongoose');
var path = require('path');
var morgan     = require("morgan");
var User = require('./models/user');
var bcrypt = require('bcrypt');
var xoauth2 = require('xoauth2');
var nodemailer = require('nodemailer');
var async = require('async');
var crypto = require('crypto');
var router = require('express-promise-router')();
var passport = require('passport');
var GooglePlusTokenStrategy = require('passport-google-plus-token');
var UserController = require('./controllers/users');
var app = express();


app.use(function(req,res,next){
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.header ('Access-Control-Allow-Methods', 'POST, GET, PUT, DELETE');
    next();
});

mongoose.connect("mongodb://localhost:27017/auth",(err,db) => {
    if(!err){
        console.log("we r connected");

    
    }
});

app.use(expressValidator({
    errorFormatter: function(param, msg, value) {
        var namespace = param.split('.')
        , root    = namespace.shift()
        , formParam = root;
  
      while(namespace.length) {
        formParam += '[' + namespace.shift() + ']';
      }
      return {
        param : formParam,
        msg   : msg,
        value : value
      };
    }
  }));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');
app.set('view options', { layout: true });
app.use(express.static(path.join(__dirname, 'public')));

app.use(morgan("dev"));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

app.use(session({
    secret: 'secret',
    saveUninitialized: true,
    resave: true
}));

app.use(passport.initialize());
app.use(passport.session());

app.use(flash());



app.get('/register',function(req,res){
    res.render('register',{});
});

app.get('/reset_pwd',function(req,res){
    res.render('reset',{});
});

app.get('/login',function(req,res){
    res.render('login',{});
});

app.get('/home',(req,res)=>{
    // console.log(req.session.user);                      
     res.render('home');
});



app.get('/home/:id',(req,res)=>{
    User.findOne({id:req.params.id},(err,user)=>{
        if(user){
            console.log('user found')
        }
    })
})

passport.use('googleToken',new GooglePlusTokenStrategy({
    clientID: '312728137910-tu78iun3igddjqglqfcadgru15l3td4p.apps.googleusercontent.com',
  clientSecret: 'HixGH1ErVvWrOxUIReazhC8v'
},async(accessToken,refreshToken, profile, done)=>{
    console.log('profile', profile);
    console.log('accessToken', accessToken);
    console.log('refreshToken', refreshToken);

    User.findOne({ "google.id": profile.id },function(err,existingUser){

        if(existingUser){
            return done(null, existingUser);
        }
            
        var newUser = new User({
            method: 'google',
            google: {
              id: profile.id,
              email: profile.emails[0].value
            }
          });

          User.createUser(newUser, function (err, user) {
            if (err) throw err;
            console.log(user);
        });

    });
}));
 

app.post('/register',  (req, res) => {

     console.log(req.body.id)

    var name = req.body.name;
	var email = req.body.email;
	var id = req.body.id;
	var password = req.body.password;
	var password2 = req.body.password2;


    var errors = req.validationErrors();
    

        User.findOne({
            id : req.body.id,
             email : req.body.email
        },function(err,existingUser){
    
            if(existingUser) {
                return res.status(409).send({message : 'Id already exists'});
    
            }
            else{
                User.findOne({'google.email': req.body.email} , (err,exists)=>{
                    if(exists){
                        return res.status(409).send({message : 'Email already exists'});
                    }

                    else{
                        var newUser = new User({
                            method : 'local',
                            
                                name: name,
                            email: email,
                            id: id,
                            password: password
                            
                            
                        });
                        User.createUser(newUser, function (err, user) {
                            if (err) throw err;
                            console.log(user);
                        });
                 req.flash('success_msg', 'You are registered and can now login');
                        res.redirect('/login');
                    }
                });
                
                }
        });
    }

);    



app.post('/login',(req,res) =>{
   
    // console.log(req.body.id)

    User.count({id:req.body.id}).exec(function(err,doc){
        if (err) res.status(500).send(error);

        
        if(doc>0){
            User.find({id:req.body.id}).exec(function(err,result){
        
                   
                    bcrypt.compare(req.body.password,result[0].password,function(err, callback){
                      
                   
                   
                        if(callback){
                            req.session.cookie.maxAge = 1 * 24 * 60 * 60 * 1000;
                            res.render('home',result[0]);

                            //res.redirect('/home');
                        }
                        else{
                            res.redirect('/login');
                        }
                    })
                })
           
        }

            else{
                res.redirect('/login');
                
            }

        }
    )

}
	
	);

app.get('/logout', function (req, res) {
        req.logout();
        req.session.cookie.maxAge = 0;
        console.log(req.session.cookie.maxAge)
        req.flash('success_msg', 'You are logged out');
    
        res.redirect('/login');
});

app.post('/reset_pwd',(req,res)=>{

        User.count({id:req.body.id}).exec(function(err,doc){
            if (err) res.status(500).send(error);

            if(doc){
                User.find({id:req.body.id}).exec(function(err,result){
                   
                    bcrypt.compare(req.body.password,result[0].password,function(err, callback){
                      
                  // console.log(result[0])
                   
                        if(callback){
                            if(req.body.new_password==req.body.new_password2){
                                bcrypt.genSalt(10, function(err, salt) {
                                    bcrypt.hash(req.body.new_password, salt, function(err, hash) {
                                        req.body.new_password = hash;
                                        console.log(req.body.new_password)

                                    User.update({id:req.body.id},{ $set: { password : req.body.new_password}  }, (err, items) => {
                                        if (err) res.status(500).send(err)
                                
                                   
                                            console.log(items);
                                            res.redirect('/login')
                                            
                                    
                                        })
                                    });
                                    
                                });
                                
                            }
                            else{
                                res.redirect('/reset_pwd')
                            }
                            
                            
                        }
                        else{
                            res.redirect('/reset_pwd')
                        }
                    })
                })
         
            }
            else{
                res.redirect('/reset_pwd')
            }
        })

});

app.get('/forgot',(req,res) =>{
    res.render('forgot', {
        user: req.user
      });
});

app.post('/forgot', function(req, res, next) {
    async.waterfall([
      function(done) {
        crypto.randomBytes(20, function(err, buf) {
          var token = buf.toString('hex');
          done(err, token);
        });
      },
      function(token, done) {
        User.findOne({ email: req.body.email }, function(err, user) {
          if (!user) {
            req.flash('error', 'No account with that email address exists.');
            return res.redirect('/forgot');
          }
  
          user.resetPasswordToken = token;
          user.resetPasswordExpires = Date.now() + 3600000; // 1 hour
  
          user.save(function(err) {
            done(err, token, user);
          });
        });
      },
      function(token, user, done) {
        var smtpTransport = nodemailer.createTransport({
          service: 'Gmail',
          auth: {
                type: 'OAuth2',
                user: 'chiragmittal.cm@gmail.com',
                clientId: '1077705428821-8esh9s4u00jetcv2luasj3u22s71dm4s.apps.googleusercontent.com' ,
                clientSecret: 'z9p-2B3xubt4wTT9y3hBSZO1' ,
                refreshToken: '1/klVSe9aNgqPjV3k-A-ivANRW4mbDTC3T9SITLJewobhT67daxlNPb4dwsJyAmgWE',
                
            
           }
        });
        var mailOptions = {
          to: user.email,
          from: 'reset@node.com',
          subject: 'Node.js Password Reset',
          text: 'You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n' +
            'Please click on the following link, or paste this into your browser to complete the process:\n\n' +
            'http://' + req.headers.host + '/reset/' + token + '\n\n' +
            'If you did not request this, please ignore this email and your password will remain unchanged.\n'
        };
        smtpTransport.sendMail(mailOptions, function(err,res) {
            console.log(user.email)
            console.log(mailOptions)
        //   req.flash('info', 'An e-mail has been sent to ' + user.email + ' with further instructions.');
        //   done(err, 'done');
        if(err){
            console.log(err);
        }else{
            console.log("Message sent: ");
        }
        

        });
      }
    ], function(err) {
      if (err) return next(err);
      res.redirect('/forgot');
    });
  });

  app.get('/reset/:token', function(req, res) {
    User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
      if (!user) {
        req.flash('error', 'Password reset token is invalid or has expired.');
        return res.redirect('/forgot');
      }
      res.render('reset_pwd', {
        user: req.user
      });
    });
  });

  app.post('/reset/:token', function(req, res) {
    User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
      if (!user) {
        req.flash('error', 'Password reset token is invalid or has expired.');
        return res.redirect('/forgot');
      }

      User.findOne({
        id : req.body.id,
    },function(err,existingUser){

        if(!existingUser) {
            return res.status(409).send({message : 'Id does not exist'});

        }
        else{
            if(req.body.new_password==req.body.new_password2){
                bcrypt.genSalt(10, function(err, salt) {
                    bcrypt.hash(req.body.new_password, salt, function(err, hash) {
                        req.body.new_password = hash;
                        console.log(req.body.new_password)

                    User.update({id:req.body.id},{ $set: { password : req.body.new_password ,resetPasswordExpires : undefined ,resetPasswordToken : undefined}  }, (err, items) => {
                        if (err) res.status(500).send(err)
                
                   
                            console.log(items);
                            res.redirect('/login')
                            
                    
                        })
                    });
                    
                });
                
            }
        }
        
      
    });
  })
});


app.route('/google_auth')
    .post(passport.authenticate('googleToken',{ session : false }), UserController.googleOAuth);



app.set('port', (process.env.PORT || 3000));

app.listen(app.get('port'), function(){
	console.log('Server started on port '+app.get('port'));
});