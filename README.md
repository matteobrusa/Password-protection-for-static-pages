# Password protection for static pages

This simple HTML document helps you protecting static pages or whole websites with no server configuration required: you can now use Dropbox, Amazon S3 or any generic hosting service to host a private, password protected site.

This small project is a byproduct of my [Tumbless blogging platform](https://github.com/matteobrusa/Tumbless) project.

## Setup

0. Upload the `index.html` document and the background image to your static hosting service.
0. Load it up in your browser, enter the password of your choice
0. It will show "wrong password", never mind. Copy the section of the URL after the # sign.
0. Create a folder with that name next to the `index.html` file
0. Upload the content that you want to protect inside the folder

The final structure will be:

```
- index.html
- background.jpg
- this-is-a-hash      <-- the SHA1 hash of your password               
  \ - index.html      <-- your original index document
```

### Is this secure?
Pretty much secure, please consider that:

0. If your hosting service offers directory listing, a visitor can bypass the protection.
1. there's no protection against brute force attack. Pick a very long and hard to guess password. 
2. The password's hash is part of the URI. __Enforce HTTPS__ to avoid man in the middle attacks.

## Troubleshooting

0. Test the [demo page](http://matteobrusa.github.io/Password-protection-for-static-pages/) in your browser with password 'secret'
0. Deploy the whole repo on your hosting, and test again.
