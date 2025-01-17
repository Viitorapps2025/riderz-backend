const jwt = require('jsonwebtoken');
const {
	
	signinSchema,
	acceptCodeSchema,
	changePasswordSchema,
	acceptFPCodeSchema,
} = require('../middlewares/validator');
 const {signupSchema}  = require('../middlewares/validator')
const User = require('../models/usersModel');
const { doHash, doHashValidation, hmacProcess } = require('../utils/hashing');
const transport = require('../middlewares/sendMail');

const crypto = require ('crypto');
const nodemailer = require('nodemailer');


exports.signup = async (req, res) => {
    console.log('Request Body:', req.body);

    const { email, password, fullname, phone } = req.body;

    try {
        const { error } = signupSchema.validate({ email, password, fullname, phone });

        if (error) {
            console.log('Validation Error:', error.details[0].message);
            return res.status(401).json({
                success: false,
                message: error.details[0].message,
            });
        }

        const existingUser = await User.findOne({
            $or: [{ email }, { phone }],
        });

        if (existingUser) {
            console.log('User already exists with email or phone:', existingUser);
            return res.status(401).json({
                success: false,
                message: 'User with this email or phone already exists!',
            });
        }

        const hashedPassword = await doHash(password, 12);

        // Generate OTP
        const otp = crypto.randomInt(100000, 999999); // Generate a 6-digit OTP
        const otpExpiration = Date.now() + 60 * 60 * 1000; // OTP valid for 60 minutes

        // Create a new user object
        const newUser = new User({
            email,
            password: hashedPassword,
            fullname,
            phone,
            verificationCode: otp,
            verificationCodeValidation: otpExpiration,
        });

        const result = await newUser.save();

        // Send OTP to the user's email
        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS, // Your email
                pass: process.env.NODE_CODE_SENDING_EMAIL_PASSWORD, // Your email password
            },
        });

        await transporter.sendMail({
            from: process.env.EMAIL,
            to: email,
            subject: 'Your Verification Code',
            text: `Your OTP is ${otp}. It is valid for 60 minutes.`,
        });

        console.log('OTP sent to email:', email);

        res.status(201).json({
            success: true,
            message: 'Your account has been created. Please verify your email with the OTP sent.',
        });
    } catch (error) {
        console.error('Error in signup:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred while creating your account. Please try again later.',
        });
    }
};

exports.verifyOtp = async (req, res) => { 
    const { email, otp } = req.body;

    try {
        const user = await User.findOne({ email }).select('+verificationCode +verificationCodeValidation');

        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found!',
            });
        }

        if (user.verified) {
            return res.status(400).json({
                success: false,
                message: 'User is already verified!',
            });
        }

        if (user.verificationCode !== otp) {
            return res.status(400).json({
                success: false,
                message: 'Invalid OTP!',
            });
        }

        if (user.verificationCodeValidation < Date.now()) {
            return res.status(400).json({
                success: false,
                message: 'OTP has expired!',
            });
        }

        // Mark the user as verified
        user.verified = true;
        user.verificationCode = undefined;
        user.verificationCodeValidation = undefined;

        await user.save();

        res.status(200).json({
            success: true,
            message: 'Your account has been verified successfully!',
        });
    } catch (error) {
        console.error('Error in OTP verification:', error);
        res.status(500).json({
            success: false,
            message: 'An error occurred while verifying your account. Please try again later.',
        });
    }
};




  
  exports.signin = async (req, res) => {
    try {
        console.log('Raw Request Body:', req.body);

        const { email, password } = req.body;
        console.log('Extracted Email:', email, 'Extracted Password:', password);

        const { error } = signinSchema.validate({ email, password });
        if (error) {
            console.log('Validation Error:', error);
            return res.status(401).json({
                success: false,
                message: error.details[0].message,
            });
        }

        const existingUser = await User.findOne({ email }).select('+password');
        if (!existingUser) {
            return res.status(401).json({
                success: false,
                message: 'User does not exist!',
            });
        }

        const result = await doHashValidation(password, existingUser.password);
        if (!result) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials!',
            });
        }

        const token = jwt.sign(
            {
                userId: existingUser._id,
                email: existingUser.email,
                verified: existingUser.verified,
            },
            process.env.TOKEN_SECRET,
            { expiresIn: '8h' }
        );

        res
            .cookie('Authorization', 'Bearer ' + token, {
                expires: new Date(Date.now() + 8 * 3600000),
                httpOnly: process.env.NODE_ENV === 'production',
                secure: process.env.NODE_ENV === 'production',
            })
            .json({
                success: true,
                token,
                message: 'Logged in successfully',
            });
    } catch (error) {
        console.error('Error in signin:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
        });
    }
};

  

exports.signout = async (req, res) => {
	res
		.clearCookie('Authorization')
		.status(200)
		.json({ success: true, message: 'logged out successfully' });
};

exports.sendVerificationCode = async (req, res) => {
	const { email } = req.body;
	try {
		const existingUser = await User.findOne({ email });
		if (!existingUser) {
			return res
				.status(404)
				.json({ success: false, message: 'User does not exists!' });
		}
		if (existingUser.verified) {
			return res
				.status(400)
				.json({ success: false, message: 'You are already verified!' });
		}

		const codeValue = Math.floor(Math.random() * 1000000).toString();
		let info = await transport.sendMail({
			from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
			to: existingUser.email,
			subject: 'verification code',
			html: '<h1>' + codeValue + '</h1>',
		});

		if (info.accepted[0] === existingUser.email) {
			const hashedCodeValue = hmacProcess(
				codeValue,
				process.env.HMAC_VERIFICATION_CODE_SECRET
			);
			existingUser.verificationCode = hashedCodeValue;
			existingUser.verificationCodeValidation = Date.now();
			await existingUser.save();
			return res.status(200).json({ success: true, message: 'Code sent!' });
		}
		res.status(400).json({ success: false, message: 'Code sent failed!' });
	} catch (error) {
		console.log(error);
	}
};

exports.verifyVerificationCode = async (req, res) => {
	const { email, providedCode } = req.body;
	try {
		const { error, value } = acceptCodeSchema.validate({ email, providedCode });
		if (error) {
			return res
				.status(401)
				.json({ success: false, message: error.details[0].message });
		}

		const codeValue = providedCode.toString();
		const existingUser = await User.findOne({ email }).select(
			'+verificationCode +verificationCodeValidation'
		);

		if (!existingUser) {
			return res
				.status(401)
				.json({ success: false, message: 'User does not exists!' });
		}
		if (existingUser.verified) {
			return res
				.status(400)
				.json({ success: false, message: 'you are already verified!' });
		}

		if (
			!existingUser.verificationCode ||
			!existingUser.verificationCodeValidation
		) {
			return res
				.status(400)
				.json({ success: false, message: 'something is wrong with the code!' });
		}

		if (Date.now() - existingUser.verificationCodeValidation > 5 * 60 * 1000) {
			return res
				.status(400)
				.json({ success: false, message: 'code has been expired!' });
		}

		const hashedCodeValue = hmacProcess(
			codeValue,
			process.env.HMAC_VERIFICATION_CODE_SECRET
		);

		if (hashedCodeValue === existingUser.verificationCode) {
			existingUser.verified = true;
			existingUser.verificationCode = undefined;
			existingUser.verificationCodeValidation = undefined;
			await existingUser.save();
			return res
				.status(200)
				.json({ success: true, message: 'your account has been verified!' });
		}
		return res
			.status(400)
			.json({ success: false, message: 'unexpected occured!!' });
	} catch (error) {
		console.log(error);
	}
};

// exports.changePassword = async (req, res) => {
// 	const { userId, verified } = req.user;
// 	const { oldPassword, newPassword } = req.body;
// 	try {
// 		const { error, value } = changePasswordSchema.validate({
// 			oldPassword,
// 			newPassword,
// 		});
// 		if (error) {
// 			return res
// 				.status(401)
// 				.json({ success: false, message: error.details[0].message });
// 		}
// 		if (!verified) {
// 			return res
// 				.status(401)
// 				.json({ success: false, message: 'You are not verified user!' });
// 		}
// 		const existingUser = await User.findOne({ _id: userId }).select(
// 			'+password'
// 		);
// 		if (!existingUser) {
// 			return res
// 				.status(401)
// 				.json({ success: false, message: 'User does not exists!' });
// 		}
// 		const result = await doHashValidation(oldPassword, existingUser.password);
// 		if (!result) {
// 			return res
// 				.status(401)
// 				.json({ success: false, message: 'Invalid credentials!' });
// 		}
// 		const hashedPassword = await doHash(newPassword, 12);
// 		existingUser.password = hashedPassword;
// 		await existingUser.save();
// 		return res
// 			.status(200)
// 			.json({ success: true, message: 'Password updated!!' });
// 	} catch (error) {
// 		console.log(error);
// 	}
// };





exports.changePassword = async (req, res) => {
    const { userId, verified } = req.user;
    const { oldPassword, newPassword } = req.body;

    try {
        // Validate passwords
        const { error, value } = changePasswordSchema.validate({ oldPassword, newPassword });
        if (error) {
            return res.status(401).json({ success: false, message: error.details[0].message });
        }

        // Check if the user is verified
        if (!verified) {
            return res.status(401).json({ success: false, message: 'You are not verified user!' });
        }

        // Find the user in the database
        const existingUser = await User.findOne({ _id: userId }).select('+password');
        if (!existingUser) {
            return res.status(401).json({ success: false, message: 'User does not exists!' });
        }

        // Validate old password
        const result = await doHashValidation(oldPassword, existingUser.password);
        if (!result) {
            return res.status(401).json({ success: false, message: 'Invalid credentials!' });
        }

        // Hash and update the new password
        const hashedPassword = await doHash(newPassword, 12);
        existingUser.password = hashedPassword;
        await existingUser.save();

        return res.status(200).json({ success: true, message: 'Password updated!!' });
    } catch (error) {
        console.log(error);
        return res.status(500).json({ success: false, message: 'An error occurred!' });
    }
};

exports.sendForgotPasswordCode = async (req, res) => {
	const { email } = req.body;
	try {
		const existingUser = await User.findOne({ email });
		if (!existingUser) {
			return res
				.status(404)
				.json({ success: false, message: 'User does not exists!' });
		}

		const codeValue = Math.floor(Math.random() * 1000000).toString();
		let info = await transport.sendMail({
			from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
			to: existingUser.email,
			subject: 'Forgot password code',
			html: '<h1>' + codeValue + '</h1>',
		});

		if (info.accepted[0] === existingUser.email) {
			const hashedCodeValue = hmacProcess(
				codeValue,
				process.env.HMAC_VERIFICATION_CODE_SECRET
			);
			existingUser.forgotPasswordCode = hashedCodeValue;
			existingUser.forgotPasswordCodeValidation = Date.now();
			await existingUser.save();
			return res.status(200).json({ success: true, message: 'Code sent!',codeValue });
		}
		res.status(400).json({ success: false, message: 'Code sent failed!' });
	} catch (error) {
		console.log(error);
	}
};

exports.verifyForgotPasswordCode = async (req, res) => {
	const { email, providedCode, newPassword } = req.body;
	try {
		const { error, value } = acceptFPCodeSchema.validate({
			email,
			providedCode,
			newPassword,
		});
		if (error) {
			return res
				.status(401)
				.json({ success: false, message: error.details[0].message });
		}

		const codeValue = providedCode.toString();
		const existingUser = await User.findOne({ email }).select(
			'+forgotPasswordCode +forgotPasswordCodeValidation'
		);

		if (!existingUser) {
			return res
				.status(401)
				.json({ success: false, message: 'User does not exists!' });
		}

		if (
			!existingUser.forgotPasswordCode ||
			!existingUser.forgotPasswordCodeValidation
		) {
			return res
				.status(400)
				.json({ success: false, message: 'something is wrong with the code!' });
		}

		
		if (
			Date.now() - existingUser.forgotPasswordCodeValidation >
			5 * 60 * 1000
		) {
			return res
				.status(400)
				.json({ success: false, message: 'code has been expired!' });
		}

		const hashedCodeValue = hmacProcess(
			codeValue,
			process.env.HMAC_VERIFICATION_CODE_SECRET
		);

		if (hashedCodeValue === existingUser.forgotPasswordCode) {
			const hashedPassword = await doHash(newPassword, 12);
			existingUser.password = hashedPassword;
			existingUser.forgotPasswordCode = undefined;
			existingUser.forgotPasswordCodeValidation = undefined;
			await existingUser.save();
			return res
				.status(200)
				.json({ success: true, message: 'Password updated!!' });
		}
		return res
			.status(400)
			.json({ success: false, message: 'unexpected occured!!' });
	} catch (error) {
		console.log(error);
	}
};




