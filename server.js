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

app.get('/home/:id',(req,res)=>{
    var user = String(req.params.id);
    console.log(user)
        console.log(user)
        res.render('home');
      
        
        

});

app.get('/register',function(req,res){
    res.render('register',{});
});

app.get('/login',function(req,res){
    res.render('login',{});
});
 

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
                var newUser = new User({
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

);    



app.post('/login',(req,res) =>{
   
    console.log(req.body.id)

    User.count({id:req.body.id}).exec(function(err,doc){
        if (err) res.status(500).send(error);

        
        if(doc>0){
            User.find({id:req.body.id}).exec(function(err,result){
        
                    bcrypt.compare(req.body.password,result[0].password,function(err, callback){
                        if(callback){
                            res.redirect('/home/'+req.body.id);
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
    
        req.flash('success_msg', 'You are logged out');
    
        res.redirect('/login');
    });



app.set('port', (process.env.PORT || 3000));

app.listen(app.get('port'), function(){
	console.log('Server started on port '+app.get('port'));
});