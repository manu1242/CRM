const mongoose = require("mongoose");
const bcrypt =require('bcryptjs')

const UserSchema = new mongoose.Schema(
    {
  name: {
    type: String,
    required: [true, "please enter your Name"],
    trim: true,
    minLength: 5,
    Maxlength: 100,
  },
  Email: {
    type: String,
    unique: true,
    lowercase: true,
    match: [/^\s+@\s+\.\S+$/, "please enter your  ValidEmail"],
  },

  password: {
    type: String,
    required: [true, "please enter your Name"],
    trim: true,
    minLength: 5,
    Maxlength: 100,
    select:false
  },
  role:{
    type:String,
    enum:["SalesRepresentative","Admin"],
    default:"user"
  }
},{timestamps:true}

);
UserSchema.pre("save",async function(next){
    if(!this.isModified("password"))
        return next();
    const salt  = await bcrypt.genSalt(10);
    this.password= await bcrypt.hash(this.password,salt);
    next();
});
UserSchema.methods.matchPassword = async function (enterPassword) {
    return await bcrypt.compare(enterPassword,this.password);
    
};

module.exports = mongoose.model('User',UserSchema);

