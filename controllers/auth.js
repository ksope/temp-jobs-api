const User = require("../models/User");
const { StatusCodes } = require("http-status-codes");
const { BadRequestError, UnauthenticatedError } = require("../errors");
//const bcrypt = require("bcryptjs"); //import hashing library function

const register = async (req, res) => {
    //const { name, email, password } = req.body;
    // if (!name || !email || !password) {
    //     throw new BadRequestError("Please provide name, email and password");
    // }

    //hash the password
    // const salt = await bcrypt.genSalt(10); //random bytes
    // const hashedPassword = await bcrypt.hash(password, salt); //pass the hashed password to the databaseand the random bytes
    // const tempUser = {name,email,password:hashedPassword};
    const user = await User.create({ ...req.body });
    const token = user.createJWT();
    res.status(StatusCodes.CREATED).json({ user: { name: user.name }, token });
};

const login = async (req, res) => {
    const { email, password } = req.body;

    //compare the password and email
    if (!email || !password) {
        throw new BadRequestError("Please provide email and password");
    }

    const user = await User.findOne({ email });
    //check if the user exists using email details
    if (!user) {
        throw new UnauthenticatedError("Invalid credentials");
    }
    const isPasswordCorrect = await user.comparePasswords(password);
    if (!isPasswordCorrect) {
        throw new UnauthenticatedError("Invalid credentials");
    }
    const token = user.createJWT();
    res.status(StatusCodes.OK).json({ user: { name: user.name }, token });
};

module.exports = {
    register,
    login,
};
