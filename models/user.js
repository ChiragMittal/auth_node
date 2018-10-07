var mongoose = require('mongoose');
var bcrypt = require('bcrypt');
var async = require('async');
const JWT = require('jsonwebtoken');


// User Schema
var UserSchema = mongoose.Schema({
	method :{
		type: String,
		enum : ['local','google'],
		required : true
	},
	
		id: {
			type: String,
			index:true
		},
		password: {
			type: String
		},
		email: {
			type: String
		},
		name: {
			type: String
		},
		resetPasswordToken: {
			type: String
		},
		  resetPasswordExpires:{
			type : Date
		  } ,
	
	google :{
		id:{
			type:String
		},
		email: {
			type: String
		}
	}
	
});

var User = module.exports = mongoose.model('User', UserSchema);

module.exports.createUser = function(newUser, callback){

	
		if(this.method == 'google'){
			console.log(this.method)
			console.log("Fuck off")
		}
		else{
			bcrypt.genSalt(10, function(err, salt) {
				bcrypt.hash(newUser.password, salt, function(err, hash) {
					newUser.password = hash;
					newUser.save(callback);
				});
			});
		}
		
	

	
};


   