# IDAFrida
A simple IDA plugin  to generate FRIDA script.

1. Edit template for functions or you can use the default template.
2. Select functions you want to trace in function window
3.  Generate & inject

![image-20220119000229980](img/image-20220119000229980.png)

## default template
IDAFrida applies template to all selected functions and then generate a single frida script.
```js
//[filename]->[funcname]
(function () {

    // @ts-ignore
    function waitForLoadLibraryNative(libName,callback){
        // @ts-ignore
        Interceptor.attach(Module.findExportByName(null, "dlopen"), {
            onEnter: function(args) {
                var pathptr = args[0];
                if (pathptr !== undefined && pathptr != null) {
                    // @ts-ignore
                    var path = ptr(pathptr).readCString();
                    // @ts-ignore
                    if (path.indexOf(libName) >= 0) {
                        this.findedLib = true;
                    }
                }
            },
            onLeave: function(retval) {
                if (this.findedLib) {
                    if(callback){
                        callback();
                        callback=null;
                    }
                }
            }
        })
    
        // @ts-ignore
        Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
            onEnter: function(args) {
                var pathptr = args[0];
                if (pathptr !== undefined && pathptr != null) {
                    // @ts-ignore
                    var path = ptr(pathptr).readCString();
                    // @ts-ignore
                    if (path.indexOf(libName) >= 0) {
                        this.findedLib = true;
                    }
                }
            },
            onLeave: function(retval) {
                if (this.findedLib) {
                    if(callback){
                        callback();
                        callback=null;
                    }
                }
            }
        });
    }
    

    // @ts-ignore
    function print_arg(addr) {
        try {
            var module = Process.findRangeByAddress(addr);
            if (module != null) return "\\n"+hexdump(addr) + "\\n";
            return ptr(addr) + "\\n";
        } catch (e) {
            return addr + "\\n";
        }
    }

    // @ts-ignore
    function hook_native_addr(funcPtr, paramsNum) {
        var module = Process.findModuleByAddress(funcPtr);
        try {
            Interceptor.attach(funcPtr, {
                onEnter: function (args) {
                    this.logs = "";
                    this.params = [];
                    // @ts-ignore
                    this.logs=this.logs.concat("So: " + module.name + "  Method: [funcname] offset: " + ptr(funcPtr).sub(module.base) + "\\n");
                    for (let i = 0; i < paramsNum; i++) {
                        this.params.push(args[i]);
                        this.logs=this.logs.concat("this.args" + i + " onEnter: " + print_arg(args[i]));
                    }
                }, onLeave: function (retval) {
                    for (let i = 0; i < paramsNum; i++) {
                        this.logs=this.logs.concat("this.args" + i + " onLeave: " + print_arg(this.params[i]));
                    }
                    this.logs=this.logs.concat("retval onLeave: " + print_arg(retval) + "\\n");
                    console.log(this.logs);
                }
            });
        } catch (e) {
            console.log(e);
        }
    }
    let module=Module.findBaseAddress("[filename]");
    if(module==null){
        waitForLoadLibraryNative("[filename]",function(){
            // @ts-ignore
            hook_native_addr(Module.findBaseAddress("[filename]").add([offset]), [nargs]);
        });
    }else{
        // @ts-ignore
        hook_native_addr(Module.findBaseAddress("[filename]").add([offset]), [nargs]);    
    }
})();

```
