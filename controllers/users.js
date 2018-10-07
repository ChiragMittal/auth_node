var User = require('../models/user');
const JWT = require('jsonwebtoken');

signToken = user => {
	return JWT.sign({
	  iss: 'CHG',
	  sub: user.id,
	  algorithm: 'RS512',
	  iat: new Date().getTime(), 
	  exp: new Date().setDate(new Date().getDate() + 1) 
	}, 'qpalzmxnskwo');
  }


  module.exports.googleOAuth = async (req, res, next) => {
    // Generate token
	console.log('got here');
	console.log(req.user);
    const token = signToken(req.user);
    res.status(200).json({ token });
  };
