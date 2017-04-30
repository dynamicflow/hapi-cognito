### hapi-cognito

Lead Maintainer: [Alessandro Oliveira](https://github.com/aro1976)

Cognito is an Amazon Web Services User Pool with full user management lifecycle.

Since AWS API Gateway has native integration with Cognito for Authentication purposes, I created this plugin 
just for basic authorization based on Cognito Groups.

In order to make it work properly you only need to:
1) Register plugin
2) Configure Group you want to check

```javascript
var plugins = [
   {
       register: require('hapi-cognito')
   }
];

server.register(plugins, function(err){
    if (err) {
        throw err;
    }

    server.route([
        {
            method : 'GET',
            path : '/check',
            handler : category_controller.listAll,
            config: {
                plugins: {
                    pagination: {
                        enabled: true
                    },
                    cognito: {
                        required: true,
                        group: 'Administrator'
                    }
                }
            }
        }
    ]);

    server.start(function() {
        logger.info('Server running at:', server.info.uri);
    });
});
```

There is a lot of improvement opportunities, feel free to send push requests.