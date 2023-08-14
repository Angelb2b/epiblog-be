const mongoose = require('mongoose')

const resourcesModelSchema = new mongoose.Schema({
    index: {
        type: String,
        required: true,
    },
    guid: {
        type: String,
        required: true,
    },
    isActive: {
        type: Boolean,
        required: true,
    },
    balance: {
        type: String,
        required: true,
    },
    picture: {
        type: String,
        required: true,
    },
    age: {
        type: Number,
        required: true,
    },
    eyeColor: {
        type: String,
        required: true,
    },
    name: {
        first: {
            type: String,
            required: true,
        },
        last: {
            type: String,
            required: true,
        }
    },
    company: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
    },
    phone: {
        type: String,
        required: true,
    },
    address: {
        type: String,
        required: true,
    },
    about: {
        type: String,
        required: true,
    },
    registered: {
        type: String,
        required: true,
    },
    latitude: {
        type: String,
        required: true,
    },
    longitude: {
        type: String,
        required: true,
    },
    tags: {
        type: Array,
        default: [],
        required: true,
    },
    range: {
        type: Array,
        default: [],
        required: true,
    },
    friends: {
        type: Array,
        default: [
            {
                id: {
                    type: String,
                    required: true,
                },
                name: {
                    type: String,
                    required: true,
                }
            }
        ],
        required: true,
    },
    greeting: {
        type: String,
        required: true,
    },
    favoriteFruit: {
        type: String,
        required: true,
    },
}, {timestamps: true, strict: true})

module.exports = mongoose.model('Resources', resourcesModelSchema, 'resources')