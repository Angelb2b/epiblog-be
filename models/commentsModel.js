const mongoose = require('mongoose')

const CommentSchema = new mongoose.Schema({
    author: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Author'
    },
    title: {
        type: String,
        required: true,
    },
    content: {
        type: String,
        required: true,
    },
    rate: {
        type: Number,
        required: true,
        max: 5,
        min: 0,
        default: 0
    }
}, {timestamps: true, strict: true})

module.exports = mongoose.model('Comment', CommentSchema, 'comments')