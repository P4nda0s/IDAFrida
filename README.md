# IDAFrida
A simple IDA plugin  to generate FRIDA script.

1. Edit template for functions or you can use the default template.
2. Select functions you want to trace in function window
3.  Generate & inject

![image-20220119000229980](img/image-20220119000229980.png)

## default template
IDAFrida applies template to all selected functions and then generate a single frida script.
```js
try {
        Interceptor.attach(Module.findBaseAddress("[filename]").add([offset]), {
        onEnter: function (args) {
            console.log("enter: [funcname]");
        },
        onLeave: function (arg) {
            console.log("leave: [funcname]");
        }
        });
    }
    catch(err) {
        console.log(err);
    }
```