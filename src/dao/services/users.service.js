import userModel from "../models/usersModel.js";

const createUser = async (user) => {
    try {
        const result = await userModel.create(user)
        return result
    } catch (error) {
        return error
    }
}

const findUserByEmail = async (username) => {
    try {
        const result = await userModel.findOne({ email: username })
        return result
    } catch (error) {
        return error
    }
}

const updateUser = async (user, updateData) => {
    try {
        result = await userModel.updateOne( { _id: user._id }, { $set: updateData } )
        return result
    } catch (error) {
        return error
    }
}

export default {
    createUser,
    findUserByEmail,
    updateUser
}