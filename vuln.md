Critical Security Vulnerability in React Server Components
December 3, 2025 by The React Team

There is an unauthenticated remote code execution vulnerability in React Server Components.

We recommend upgrading immediately.

On November 29th, Lachlan Davidson reported a security vulnerability in React that allows unauthenticated remote code execution by exploiting a flaw in how React decodes payloads sent to React Server Function endpoints.

Even if your app does not implement any React Server Function endpoints it may still be vulnerable if your app supports React Server Components.

This vulnerability was disclosed as CVE-2025-55182 and is rated CVSS 10.0.

The vulnerability is present in versions 19.0, 19.1.0, 19.1.1, and 19.2.0 of:

react-server-dom-webpack
react-server-dom-parcel
react-server-dom-turbopack
Immediate Action Required 

A fix was introduced in versions 19.0.1, 19.1.2, and 19.2.1. If you are using any of the above packages please upgrade to any of the fixed versions immediately.

If your app’s React code does not use a server, your app is not affected by this vulnerability. If your app does not use a framework, bundler, or bundler plugin that supports React Server Components, your app is not affected by this vulnerability.

Affected frameworks and bundlers 

Some React frameworks and bundlers depended on, had peer dependencies for, or included the vulnerable React packages. The following React frameworks & bundlers are affected: next, react-router, waku, @parcel/rsc, @vitejs/plugin-rsc, and rwsdk.

We will update this post with upgrade instructions on how to upgrade as they become available.

Hosting Provider Mitigations 

We have worked with a number of hosting providers to apply temporary mitigations.

You should not depend on these to secure your app, and still update immediately.

Vulnerability overview 

React Server Functions allow a client to call a function on a server. React provides integration points and tools that frameworks and bundlers use to help React code run on both the client and the server. React translates requests on the client into HTTP requests which are forwarded to a server. On the server, React translates the HTTP request into a function call and returns the needed data to the client.

An unauthenticated attacker could craft a malicious HTTP request to any Server Function endpoint that, when deserialized by React, achieves remote code execution on the server. Further details of the vulnerability will be provided after the rollout of the fix is complete.

Update Instructions 

Next.js 

All users should upgrade to the latest patched version in their release line:

npm install next@15.0.5   // for 15.0.x
npm install next@15.1.9   // for 15.1.x
npm install next@15.2.6   // for 15.2.x
npm install next@15.3.6   // for 15.3.x
npm install next@15.4.8   // for 15.4.x
npm install next@15.5.7   // for 15.5.x
npm install next@16.0.7   // for 16.0.x
If you are on Next.js 14.3.0-canary.77 or a later canary release, downgrade to the latest stable 14.x release:

npm install next@14
See the Next.js changelog for more info.

React Router 

If you are using React Router’s unstable RSC APIs, you should upgrade the following package.json dependencies if they exist:

npm install react@latest
npm install react-dom@latest
npm install react-server-dom-parcel@latest
npm install react-server-dom-webpack@latest
npm install @vitejs/plugin-rsc@latest
Expo 

Upgrade to the latest react-server-dom-webpack:

npm install react@latest react-dom@latest react-server-dom-webpack@latest
Redwood SDK 

Ensure you are on rwsdk>=1.0.0-alpha.0

For the latest beta version:

npm install rwsdk@latest
Upgrade to the latest react-server-dom-webpack:

npm install react@latest react-dom@latest react-server-dom-webpack@latest
See Redwood docs for more migration instructions.

Waku 

Upgrade to the latest react-server-dom-webpack:

npm install react@latest react-dom@latest react-server-dom-webpack@latest
@vitejs/plugin-rsc 

Upgrade to the latest RSC plugin:

npm install react@latest react-dom@latest @vitejs/plugin-rsc@latest
react-server-dom-parcel 

Update to the latest version:

npm install react@latest react-dom@latest react-server-dom-parcel@latest
react-server-dom-turbopack 

Update to the latest version:

npm install react@latest react-dom@latest react-server-dom-turbopack@latest
react-server-dom-webpack 

Update to the latest version:

npm install react@latest react-dom@latest react-server-dom-webpack@latest
Timeline 

November 29th: Lachlan Davidson reported the security vulnerability via Meta Bug Bounty.
November 30th: Meta security researchers confirmed and began working with the React team on a fix.
December 1st: A fix was created and the React team began working with affected hosting providers and open source projects to validate the fix, implement mitigations and roll out the fix
December 3rd: The fix was published to npm and the publicly disclosed as CVE-2025-55182.
