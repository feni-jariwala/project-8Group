var mongoose=require('mongoose');
var Schema=mongoose.Schema;
var bcrypt=require('bcrypt-nodejs');
var userSchema=new Schema({
    emailId:{type:String,required:true},
    password:{type:String,required:true},
    username:{type:String,required:true},
    cnno:{type:String,required:true},
    
});

userSchema.method('encryptPassword', function(password) {
    return bcrypt.hashSync(password, bcrypt.genSaltSync(5), null);
  });
  
  /*userSchema.method('validPassword', function(password) {
    return bcrypt.compareSync(password, this.password);
  });*/
  userSchema.methods.validPassword=function(password){
    return bcrypt.compareSync(password, this.password);
  }
  module.exports=mongoose.model('User',userSchema);