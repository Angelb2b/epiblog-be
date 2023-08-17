

/* const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'blog-posts', 
    allowed_formats: ['jpg', 'jpeg', 'png'] 
  }
}); */
const express = require('express');
const mongoose = require('mongoose');
const BlogPostModel = require('../models/blogPostModel');
const { postBodyParams, validatePostBody } = require('../Validators/blogPostValidator');
const authorModel = require('../models/authorModel');
const commentsModel = require('../models/commentsModel');
const imagePost = require('../middleware/uploadImg');
const fs = require('fs');
const path = require('path');

const multer = require('multer');
const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const crypto = require('crypto');

const app = express();
const router = express.Router();

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'blog-posts',
    allowed_formats: ['jpg', 'jpeg', 'png']
  }
});

const uploads = multer({ storage: storage });

app.post('/blogPosts/internalUpload', uploads.single('cover'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: "L'upload dell'immagine non è riuscito" });
    }

    const user = await authorModel.findById(req.body.author);

    const newPost = new BlogPostModel({
      category: req.body.category,
      title: req.body.title,
      cover: req.file.path, // Utilizza l'URL del file caricato sul server come URL della copertina
      readTime: {
        value: req.body.readTimeValue,
        unit: req.body.readTimeUnit
      },
      author: user,
      content: req.body.content
    });

    const blogPost = await newPost.save();
    await authorModel.updateOne({ _id: user }, { $push: { posts: newPost } });

    fs.unlinkSync(path.join(__dirname, '../uploads/', req.file.filename));

    res.status(201).send({
      img: req.file.path,
      statusCode: 201,
      message: 'Post salvato con successo',
      payload: blogPost
    });
  } catch (error) {
    res.status(500).send({
      statusCode: 500,
      message: "Errore interno del server",
      error
    });
  }
});

router.get('/blogPosts/title', async (req, res) => {
  const { postTitle } = req.query;

  try {
    const postByTitle = await BlogPostModel.find({
      title: {
        $regex: '.*' + postTitle + '.*',
        $options: 'i'
      }
    });

    if (!postByTitle || postByTitle.length <= 0) {
      return res.status(404).send({
        statusCode: 404,
        message: `Post with title ${postTitle} doesn't exist!`
      });
    }

    res.status(200).send({
      statusCode: 200,
      postByTitle,
    });
  } catch (error) {
    res.status(500).send({
      statusCode: 500,
      message: 'Internal server Error',
      error,
    });
  }
});

router.get('/blogPosts', async (req, res) => {
  try {
    const blogPosts = await BlogPostModel.find()
      .populate("author", "name surname avatar")
      .populate("comments", "title content rate");

    res.status(200).send({
      statusCode: 200,
      blogPosts: blogPosts
    });
  } catch (error) {
    res.status(500).send({
      statusCode: 500,
      message: 'Internal server Error',
            error,
        })
    }
})

//! GET
router.get('/blogPosts', async (req, res) => {
    try {
        const blogPosts = await BlogPostModel.find()
            .populate("author", "name surname avatar")
            .populate("comments", "title content rate")

        res.status(200).send({
            statusCode: 200,
            blogPosts: blogPosts
        })
    } catch (error) {
        res.status(500).send({
            statusCode: 500,
            message: 'Internal server Error',
            error,
        })
    }

})

//!POST
router.post('/blogPosts/internalUpload', uploads.single('cover'), async (req, res) => {
    try {
        if(!req.file) {
            return res.status(400).json({message: "L'upload dell'immagine non è riuscito"});
        }

        const user = await authorModel.findById(req.body.author)

        let coverURL = req.file.path;

        const newPost = new BlogPostModel({
            category: req.body.category,
            title: req.body.title,
            cover: coverURL, 
            readTime: {
                value: req.body.readTimeValue,
                unit: req.body.readTimeUnit
            },
            author: user,
            content: req.body.content
        });

        const blogPost = await newPost.save();
        await authorModel.updateOne({_id: user}, {$push: {posts: newPost}})

        res.status(201).send({
            img: req.file.path,
            statusCode: 201,
            message: 'Post salvato con successo',
            payload: blogPost
        })
    } catch (error) {
        res.status(500).send({
            statusCode: 500,
            message: "Errore interno del server",
            error
        })
    }
});


//!PATCH
router.patch('/blogPosts/:id', async (req, res) => {
    const { id } = req.params;

    const blogPostExists = await BlogPostModel.findById(id);

    if (!blogPostExists) {
        return res.status(404).send({
            statusCode: 404,
            message: `Post with id ${id} non trovato`
        })
    }

    try {
        const dataToUpdate = req.body;
        const options = { new: true };

        const patchRes = await BlogPostModel.findByIdAndUpdate(id, dataToUpdate, options);

        res.status(200).send({
            statusCode: 200,
            message: "Post modified successfully",
            patchRes,
        })
    } catch (error) {
        res.status(500).send({
            statusCode: 500,
            message: "Internal server error",
            error,
        })
    }
})

//!DELETE
router.delete('/blogPosts/:id', async (req, res) => {
    const { id } = req.params;
    const blogPostExists = await BlogPostModel.findById(id);
    const user = await authorModel.findById(blogPostExists.author)


    if (!blogPostExists) {
        return res.status(404).send({
            statusCode: 404,
            message: `Post with id ${id} not found`
        })
    }

    try {
        const postToDelete = await BlogPostModel.findByIdAndDelete(id)
        await user.updateOne({$pull: {posts: id}})

        res.status(200).send({
            statusCode: 200,
            message: 'Post deleted successuffly',
            postToDelete
        })
    } catch (error) {
        res.status(500).send({
            statusCode: 500,
            message: "Internal server error",
            error,
        })
    }
})

//!FIND BY ID

router.get('/blogPosts/:id', async (req, res) => {
    const { id } = req.params;

    try {
        const blogPostsById = await BlogPostModel.findById(id)
        .populate("author", "name surname avatar")
        .populate("comments")

        res.status(200).send({
            statusCode: 200,
            blogPostsById
        })
    } catch (error) {
        res.status(500).send({
            statusCode: 500,
            message: 'Internal server Error',
            error,
        })
    }

})

router.patch('/blogPosts/:id/patchComment/:commentId', async(req, res) => {
    const { id, commentId } = req.params;

    const dataToUpdate = req.body;
    const options = { new: true };

    try {
        const patchRes = await commentsModel.findByIdAndUpdate(commentId, dataToUpdate, options)

        res.status(200).send({
            statusCode: 200,
            message: "Comment modified successfully",
            patchRes,
        })
    } catch (error) {
        res.status(500).send({
            statusCode: 500,
            message: "Internal server error",
            error,
        })
    }

})

router.get('/blogPosts/:id/comments', async (req, res) => {
    const { id } = req.params;

    try {
        const blogPostsById = await BlogPostModel.findById(id)
        .populate({
            path: 'comments',
            populate: {
                path: 'author'
            }
        })
        const blogComments = blogPostsById.comments;
        

        res.status(200).send({
            statusCode: 200,
            blogComments
        })
    } catch (error) {
        res.status(500).send({
            statusCode: 500,
            message: 'Internal server Error',
            error,
        })
    }

})

router.get('/blogPosts/:id/comments/:commentId', async (req, res) => {
    const { id, commentId } = req.params;

    try {
        const blogPostsById = await BlogPostModel.findById(id)
        const commentById = await commentsModel.findById(commentId)
        .populate("author");

        res.status(200).send({
            statusCode: 200,
            commentById
        })
    } catch (error) {
        res.status(500).send({
            statusCode: 500,
            message: 'Internal server Error',
            error,
        })
    }

})


router.post('/blogPosts/:id/newComment', async (req, res) => {
    const { id } = req.params;
    const post = await BlogPostModel.findById(id)
    const author = await authorModel.findOne({_id: req.body.author})
    
    const newComment = new commentsModel({
        author: author._id,
        title: req.body.title,
        content: req.body.content,
        rate: req.body.rate,
    })
    try {
        const comment = await newComment.save();
        await post.updateOne({$push: {comments: newComment}})

        res.status(201).send({
            statusCode: 201,
            message: 'Comment saved successfully',
            payload: comment,
        })
    } catch (error) {
        res.status(500).send({
            statusCode: 500,
            message: 'Internal server Error',
            error,
        })
    }
})

router.delete('/blogPosts/:id/deleteComment/:commentId', async(req, res) => {
    const { id, commentId } = req.params

    try {
        const blogPostsById = await BlogPostModel.findById(id)
        const commentById = await commentsModel.findByIdAndDelete(commentId)
        await blogPostsById.updateOne({$pull: {comments: commentId}})

        res.status(200).send({
            statusCode: 200,
            message: 'Comment deleted successuffly',
            commentById
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
