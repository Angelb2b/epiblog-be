const express = require('express')
const mongoose = require('mongoose')
const ResourcesModel = require('../models/resourcesModel');


const router = express.Router();


//!Trova tutte le risorse con isActive: true
router.get('/resources/isActive', async (req, res) => {

    try {
        const activePosts = await ResourcesModel.find({
            isActive: true,
        })


        res.status(200).send({
            statusCode: 200,
            activePosts,
        })
    } catch (error) {
        res.status(500).send({
            statusCode: 500,
            message: 'Internal server Error',
            error,
        })
    }
})


//!Trova tutte le risorse con company = "FITCORE" e ritorna solo mail
router.get('/resources/company', async (req, res) => {
    const { name } = req.query;
    if (!name) {
        return res.status(404).send({
            message: 'Company Name is required'
        })
    }

    try {
        const activePosts = await ResourcesModel.find({
            company: {
                $regex: name,
                $options: "i"
            }
        }, { email: 1 })

        res.status(200).send({
            statusCode: 200,
            activePosts
        })
    } catch (error) {
        res.status(500).send({
            statusCode: 500,
            message: 'Internal server Error',
            error,
        })
    }
})

//!Trova tutte le risorse con eyeColor != color
router.get('/resources/notEyeColor', async (req, res) => {
    const { color } = req.query;
    if (!color) {
        return res.status(404).send({
            message: 'Eye color is required'
        })
    }
    try {
        const activePosts = await ResourcesModel.find({
            eyeColor: { $ne: color }
        }, { "name.first": 1, "name.last": 1, eyeColor: 1 })

        res.status(200).send({
            statusCode: 200,
            activePosts
        })
    } catch (error) {
        res.status(500).send({
            statusCode: 500,
            message: 'Internal server Error',
            error,
        })
    }
})


//!Trova tutte le risorse con eyeColor = color1 or color2
router.get('/resources/eyeColor', async (req, res) => {
    const { color1, color2 } = req.query;
    let filter = {};
    if (!color1 && !color2) {
        return res.status(404).send({
            message: "At least one color is required"
        })
    }
    if (color1) {
        filter = {
            eyeColor: {
                $regex: color1,
                $options: 'i'
            }
        }
    }
    if (color2) {
        filter = {
            $or: [{
                eyeColor: {
                    $regex: color1,
                    $options: 'i'
                }
            },
            {
                eyeColor: {
                    $regex: color2,
                    $options: 'i'
                }
            }

            ]
        }
    }
    try {
        const activePosts = await ResourcesModel.find(filter, { "name.first": 1, "name.last": 1, eyeColor: 1 })


        res.status(200).send({
            statusCode: 200,
            activePosts,
        })
    } catch (error) {
        res.status(500).send({
            statusCode: 500,
            message: 'Internal server Error',
            error,
        })
    }
})

//!Trova tutte le risorse con 26<age<=30
router.get('/resources/olderThen', async (req, res) => {
    const { ageA, ageB } = req.query;
    let filter = {}
    if (!ageA && !ageB) {
        return res.status(404).send({
            statusCode: 404,
            message: "Age is required"
        })
    }
    if (ageA) {
        filter = {
            age: { $gt: ageA }
        }
    }
    if (ageB) {
        filter = {
            $and: [
                { age: { $gt: ageA } },
                { age: { $lte: ageB } }
            ]
        }
    }
    try {
        const olderThen = await ResourcesModel.find(filter)


        res.status(200).send({
            statusCode: 200,
            olderThen,
        })
    } catch (error) {
        res.status(500).send({
            statusCode: 500,
            message: 'Internal server Error',
            error,
        })
    }
})


//!Tutte le risorse
router.get('/resources', async (req, res) => {
    try {
        const resources = await ResourcesModel.find()
        const totalResources = await ResourcesModel.count()

        res.status(200).send({
            totalResources,
            statusCode: 200,
            resources: resources
        })
    } catch (error) {
        res.status(500).send({
            statusCode: 500,
            message: 'Internal server Error',
            error,
        })
    }
})






module.exports = router;