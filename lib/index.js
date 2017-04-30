'use strict';

// Load modules

const Boom = require('boom');
const Hoek = require('hoek');
const jwt  = require('jsonwebtoken');

// Declare internals

const internals = {};

exports.register  = function(server, options, next) {

    const config = Hoek.clone(options);
    if (typeof config.debug === 'undefined') {
        config.debug = false;
    }

    server.ext('onPostAuth', function(request, reply)  {

        var settings = request._route.settings;

        if (settings && settings.plugins && settings.plugins.cognito && (
                settings.plugins.cognito.required || settings.plugins.cognito.group)) {

            if (config.debug) console.log("cognito authorization required");

            var decoded = jwt.decode(request.headers.authorization);
            if (decoded === null) {
                console.error("cognito cannot decode jwt token");
                return reply(Boom.unauthorized(null, 'Cognito', null));
            }

            var credentials = {
                username: decoded['cognito:username'],
                firstName: decoded['given_name'],
                lastName: decoded['family_name'],
                email: decoded['email'],
                id: decoded['sub'],
                groups: decoded['cognito:groups'] ? decoded['cognito:groups'] : []
            };

            request.credentials = credentials;

            if (settings.plugins.cognito.group) {
                if (config.debug) console.log("cognito group check", settings.plugins.cognito.group, credentials.groups);
                for (var i=0; i<credentials.groups.length; i++) {
                    if (settings.plugins.cognito.group === credentials.groups[i]) {
                        return reply.continue();
                    }
                }
                return reply(Boom.unauthorized(null, 'Cognito', null));
            }
        }

        reply.continue();
    });

    next();
};

exports.register.attributes = {
    pkg: require('../package.json')
};