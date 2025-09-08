import express from 'express';
import dotenv from 'dotenv';
import sgMail from '@sendgrid/mail';
import crypto from 'crypto';


dotenv.config();
const app = express();

// Configure SendGrid
sgMail.setApiKey(process.env.SENDGRID_API_KEY);
// sgMail.setDataResidency('eu');
// Uncomment if using a regional EU subuser


app.use(express.json({
    verify: (req, res, buf) => {
        req.rawBody = buf;
    }
}));







function verifySignature(req, res, next) {
    const signature = req.headers["x-signature"];
    const timestamp = req.headers["x-timestamp"];

    if (!signature) {
      return res.status(401).json({ error: "Unauthorized: missing signature" });
    }

  
    const payloadBuffer = req.rawBody || Buffer.from(JSON.stringify(req.body));
    const expectedSignature = crypto
      .createHmac("sha256", process.env.SECRET_KEY)
      .update(timestamp + req.rawBody)
      .digest("hex");
  

  
    if (signature !== expectedSignature) {
      return res.status(401).json({ error: "Unauthorized: invalid signature" });
    }
  
    next();
  }


// Route to send emails using SendGrid
app.post('/send-email', verifySignature, async (req, res) => {
    try {
        const { to, subject, html, text } = req.body;
        const from = process.env.SENDGRID_FROM || process.env.EMAIL_USER;

        const msg = { to, from, subject, html, text };
        await sgMail.send(msg);

        res.json({ message: 'Email sent successfully' });
    } catch (error) {
        return res.status(500).json({
            error: 'Failed to send email',
            code: error.code,
            response: error.response,
        });
    }
});


const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});


export default app; 