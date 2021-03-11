const express = require('express');
const { profile_url } = require('gravatar');
const router = express.Router();
const request = require('request');
const config = require('config');

const { body, validationResult } = require('express-validator');

const auth = require('./../../middleware/auth')
const Profile = require('./../../models/Profile');
const User = require('./../../models/User');

// @route GET api/profile/me
// @desc Get current user profile
// @access Private
router.get('/me', auth, async (req, res) => {
    try {
        const profile = await Profile.findOne({user: req.user.id}).populate('user', ['name', 'avatar']);

        if(!profile) {
            return res.status(400).json({
                msg: 'There is no profile for this user!'
            })
        }

        res.json(profile);

    } catch(err) {
        console.error(err.message);
        res.status(500).send('Server Error!');
    }
});


// @route POST api/profile
// @desc Create or Update user profile
// @access Private
router.post('/', [ auth, [
    body('status', 'Status is required!').not().isEmpty(),
    body('skills', 'Skills is required').not().isEmpty()
] ], async (req, res) => {
    const errors = validationResult(req);
    if(!errors.isEmpty() ) {
        return res.status(400).json({ errors: errors.array() });
    }

    const {
        company,
        website,
        location,
        bio,
        status,
        githubusername,
        skills,
        youtube,
        facebook,
        twitter,
        instagram,
        linkedin
    } = req.body;

    // Build profile object
    const profileFields = {};
    profileFields.user = req.user.id;
    if(company) profileFields.company = company;
    if(website) profileFields.website = website;
    if(location) profileFields.location = location;
    if(bio) profileFields.bio = bio;
    if(status) profileFields.status = status;
    if(githubusername) profileFields.githubusername = githubusername;

    if(skills) {
        profileFields.skills = skills.split(',').map(skill => skill.trim());
    }

    // Build social object
    profileFields.social = {};
    if(youtube) profileFields.social.youtube = youtube;
    if(twitter) profileFields.social.twitter = twitter;
    if(facebook) profileFields.social.facebook = facebook;
    if(linkedin) profileFields.social.linkedin = linkedin;
    if(instagram) profileFields.social.instagram = instagram;

    try {
        let profile = await Profile.findOne({ user: req.user.id });

        // update
        if(profile) {
            profile = await Profile.findOneAndUpdate(
                { user: req.user.id },
                { $set: profileFields },
                { new: true }
            );

            return res.json(profile);
        }

        // create
        profile = new Profile(profileFields);

        await profile.save();
        res.json(profile);

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error!');
    }

});

// @route GET api/profile
// @desc Get all profiles
// @access Public
router.get('/', async (req, res) => {
    try {
        const profiles = await Profile.find().populate('user', ['name', 'avatar']);
        res.json(profiles);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error!');
    }
});

// @route GET api/profile/user/:user_id
// @desc Get profile by user ID
// @access Public
router.get('/user/:user_id', async (req, res) => {
    try {
        const profile = await Profile.findOne({ user: req.params.user_id }).populate('user', ['name', 'avatar']);

        if(!profile) 
            return res.status(400).json({
            msg: 'Profile not found!'
            });

        res.json(profile);
    } catch (err) {
        console.error(err.message);
        if(err.kind == 'ObjectId') 
            return res.status(400).json({
                msg: 'Profile not found!'
            });
        res.status(500).send('Server Error!');
    }
});

// @route DELETE api/profile
// @desc Delete profile, user and posts all at once
// @access Private
router.delete('/', auth, async (req, res) => {
    try {
        //  Remove Posts

        // Remove Profile
        await Profile.findOneAndRemove({ user: req.user.id });

        // Remove User
        await User.findOneAndRemove({ _id: req.user.id });
        res.json({ msg: 'Deletion Successful!'});

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error!');
    }
});

// @route PUT api/profile/experience
// @desc Add / Update experience to the profile
// @access Private
router.put('/experience', 
    [ auth, 
        [
            body('title', 'Title is requireed!').not().isEmpty(),
            body('company', 'Company is required!').not().isEmpty(),
            body('from', 'Joining Date is required!').not().isEmpty()
        ]
    ], async (req, res) => {
        const errors = validationResult(req);
        if(!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const {
            title,
            company,
            location,
            from,
            to,
            current,
            description
        } = req.body;

        const newExp = {
            // same as-> title: title,
            title,
            company,
            location,
            from,
            to,
            current,
            description
        }

        try {
            const profile = await Profile.findOne({ user: req.user.id });

            profile.experience.unshift(newExp);

            await profile.save();

            res.json(profile);
            
        } catch (err) {
            console.error(err.message);
            res.status(500).send('Server Error!');
            
        }
});

// @route DELETE api/profile/experience/:exp_id
// @desc Add / Delete experience from the profile
// @access Private
router.delete('/experience/:exp_id', auth, async (req, res) => {
    try {
        const profile = await Profile.findOne({ user: req.user.id });

        //  Get index of exp to be removed
        if(profile.experience.map(item => item.id).indexOf(req.params.exp_id) == -1) {
            return res.status(400).json({ msg: "Experience not found!"})
        }

       const removeIndex = profile.experience.map(item => item.id).indexOf(req.params.exp_id);

       profile.experience.splice(removeIndex, 1);

       await profile.save();
       res.json(profile);

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error!');
    }
});

// @route PUT api/profile/education
// @desc Add / Update education to the profile
// @access Private
router.put('/education', 
    [ auth, 
        [
            body('school', 'School is requireed!').not().isEmpty(),
            body('degree', 'Degree is required!').not().isEmpty(),
            body('fieldofstudy', 'Field of study is required!').not().isEmpty(),
            body('from', 'Joining Date is required!').not().isEmpty()
        ]
    ], async (req, res) => {
        const errors = validationResult(req);
        if(!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const {
            school,
            degree,
            fieldofstudy,
            from,
            to,
            current,
            description
        } = req.body;

        const newEdu = {
            // same as-> title: title,
            school,
            degree,
            fieldofstudy,
            from,
            to,
            current,
            description
        }

        try {
            const profile = await Profile.findOne({ user: req.user.id });

            profile.education.unshift(newEdu);

            await profile.save();

            res.json(profile);
            
        } catch (err) {
            console.error(err.message);
            res.status(500).send('Server Error!');
            
        }
});

// @route DELETE api/profile/education/:edu_id
// @desc Add / Delete education from the profile
// @access Private
router.delete('/education/:edu_id', auth, async (req, res) => {
    try {
        const profile = await Profile.findOne({ user: req.user.id });

        //  Get index of edu to be removed
        if(profile.education.map(item => item.id).indexOf(req.params.edu_id) == -1) {
            return res.status(400).json({ msg: "Education not found!"})
        }

       const removeIndex = profile.education.map(item => item.id).indexOf(req.params.edu_id);

       profile.education.splice(removeIndex, 1);

       await profile.save();
       res.json(profile);

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error!');
    }
});

// @route GET api/profile/github/:username
// @desc Add / Get repositories from github
// @access Public
router.get('/github/:username', async (req, res) => {
    try {
        const options = {
            uri: `https://api.github.com/users/${req.params.username}/repos?per_page=5&sort=created:asc&client_id=${config.get('githubClientId')}&clientSecret=${config.get('githubSecret')}`,
            method: 'GET',
            headers: { 'user-agent': 'node.js' }
        };

        request( options, (error, response, body) => {
            if(error) console.error(error);

            if(response.statusCode !== 200) {
                return res.status(404).json({ msg: 'No Github profile found!'});
            }

            res.json(JSON.parse(body));
        });
        
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error!');
    }
});

module.exports = router;