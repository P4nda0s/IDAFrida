# NOTE: only for IDA with PySide6 support versions

import ida_kernwin
import ida_name
import idaapi


###################
# from: https://github.com/igogo-x86/HexRaysPyTools
class ActionManager(object):
    def __init__(self):
        self.__actions = []

    def register(self, action):
        self.__actions.append(action)
        idaapi.register_action(
            idaapi.action_desc_t(action.name, action.description, action, action.hotkey)
        )

    def initialize(self):
        pass

    def finalize(self):
        for action in self.__actions:
            idaapi.unregister_action(action.name)


action_manager = ActionManager()


class Action(idaapi.action_handler_t):
    """
    Convenience wrapper with name property allowing to be registered in IDA using ActionManager
    """
    description = None
    hotkey = None

    def __init__(self):
        super(Action, self).__init__()

    @property
    def name(self):
        return "FridaIDA:" + type(self).__name__

    def activate(self, ctx):
        # type: (idaapi.action_activation_ctx_t) -> None
        raise NotImplementedError

    def update(self, ctx):
        # type: (idaapi.action_activation_ctx_t) -> None
        raise NotImplementedError


############################################################################
import ida_funcs
import idc
import json
import os

from PySide6 import QtCore
from PySide6.QtWidgets import (
    QApplication,
    QDialog, 
    QHBoxLayout, 
    QVBoxLayout, 
    QTextEdit, 
    QLineEdit, 
    QDialogButtonBox, 
    QPushButton
)

# [offset] => offset of target function in hex value format.
# [funcname] => function name
# [filename] => input file name of IDA. e.g. xxx.so / xxx.exe

default_func_hook_template = """

//[filename]->[funcname]
(function () {

    // @ts-ignore
    function waitForLoadLibraryNative(libName,callback){
        // @ts-ignore
        Interceptor.attach(Module.findGlobalExportByName("dlopen"), {
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
        Interceptor.attach(Module.findGlobalExportByName("android_dlopen_ext"), {
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
            return ""+addr+"(pointer)   memory dump:\\n"+hexdump(addr) + "\\n";
        } catch (e) {
            return addr + "\\n";
        }
    }

    // @ts-ignore
    function hook_native_addr(funcPtr, paramsNum) {
        var module = Process.findModuleByAddress(funcPtr);
        if(module==null){
            module=Process.findModuleByName("[filename]")
        }
        try {
            Interceptor.attach(funcPtr, {
                onEnter: function (args) {
                    this.logs = "";
                    this.params = [];
                    // @ts-ignore
                    this.logs=this.logs.concat("So: " + module.name +"["+module.base+"]" + "  Method: [funcname] offset: " + ptr(funcPtr).sub(module.base) + "\\n");
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
    let module=Process.getModuleByName("[filename]");
    if(module==null){
        waitForLoadLibraryNative("[filename]",function(){
            // @ts-ignore
            hook_native_addr(Process.getModuleByName("[filename]").base.add([offset]), [nargs]);
        });
    }else{
        // @ts-ignore
        hook_native_addr(Process.getModuleByName("[filename]").base.add([offset]), [nargs]);
    }
})();

"""

default_address_hook_template = """

//[filename]->[address]: [registers]
(function () {

    // @ts-ignore
    function waitForLoadLibraryNative(libName,callback){
        // @ts-ignore
        Interceptor.attach(Module.findGlobalExportByName("dlopen"), {
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
        Interceptor.attach(Module.findGlobalExportByName("android_dlopen_ext"), {
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
            if (module != null) return ""+addr+"(pointer)   memory dump:\\n"+hexdump(addr) + "\\n";
            return ptr(addr) + "\\n";
        } catch (e) {
            return addr + "\\n";
        }
    }

    // @ts-ignore
    function hook_native_addr(address, registers) {
        var module = Process.findModuleByAddress(address);
        try {
            Interceptor.attach(address, {
                onEnter: function (args) {
                    this.logs = "";
                    // @ts-ignore
                    this.logs=this.logs.concat("So: " + module.name +"["+module.base+"]" + "  Address: " + ptr(address).sub(module.base) + " [registers] " + "\\n");

                    if(registers!=null&&registers.trim()!==""){
                        for (let register of registers.trim().split(" ")) {
                            if(register==null||register.trim()=="")continue;
                            // @ts-ignore
                            this.logs=this.logs.concat("this.context." + register + " onEnter: " + print_arg(this.context[register.trim()]));
                        }
                    }
                    console.log(this.logs);
                }
            });
        } catch (e) {
            console.log(e);
        }
    }
    let module=Process.getModuleByName("[filename]");
    if(module==null){
        waitForLoadLibraryNative("[filename]",function(){
            // @ts-ignore
            hook_native_addr(Process.getModuleByName("[filename]").base.add([address]), "[registers]");
        });
    }else{
        // @ts-ignore
        hook_native_addr(Process.getModuleByName("[filename]").base.add([address]), "[registers]");
    }
})();

"""


class Configuration:
    def __init__(self) -> None:
        self.frida_cmd = """frida -U --attach-name="com.example.app" -l gen.js --no-pause"""
        self.template_func = default_func_hook_template
        self.template_address = default_address_hook_template
        if os.path.exists("IDAFrida.json"):
            self.load()

    def set_frida_cmd(self, s):
        self.frida_cmd = s
        self.store()

    def set_template_func(self, s):
        self.template_func = s
        self.store()

    def set_template_address(self, s):
        self.template_address = s
        self.store()

    def reset(self):
        self.__init__()

    def store(self):
        try:
            data = {"frida_cmd": self.frida_cmd, "template_func": self.template_func,
                    "template_address": self.template_address}
            open("IDAFrida.json", "w").write(json.dumps(data))
        except Exception as e:
            print(e)

    def load(self):
        try:
            data = json.loads(open("IDAFrida.json", "r").read())
            self.frida_cmd = data["frida_cmd"]
            self.template_func = data["template_func"]
            self.template_address = data["template_address"]
        except Exception as e:
            print(e)


global_config = Configuration()


class FuncConfigurationUI(QDialog):
    def __init__(self, conf: Configuration) -> None:
        super(FuncConfigurationUI, self).__init__()
        self.conf = conf
        self.setFixedWidth(700)
        self.setFixedHeight(700)
        self.edit_template = QTextEdit()
        self.edit_template.setPlainText(self.conf.template_func)
        layout = QVBoxLayout()
        layout.addWidget(self.edit_template)
        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btn_box.setCenterButtons(True)
        btn_box.accepted.connect(self.accepted)
        btn_box.rejected.connect(self.rejected)
        layout.addWidget(btn_box)
        self.setLayout(layout)

    def rejected(self):
        self.close()

    def accepted(self):
        self.conf.set_template_address(self.edit_template.toPlainText())
        self.conf.store()
        self.close()


class AddressConfigurationUI(QDialog):
    def __init__(self, conf: Configuration) -> None:
        super(AddressConfigurationUI, self).__init__()
        self.setFixedWidth(700)
        self.setFixedHeight(700)
        self.conf = conf
        self.edit_template = QTextEdit()
        self.edit_template.setPlainText(self.conf.template_address)
        layout = QVBoxLayout()
        layout.addWidget(self.edit_template)
        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btn_box.setCenterButtons(True)
        btn_box.accepted.connect(self.accepted)
        btn_box.rejected.connect(self.rejected)
        layout.addWidget(btn_box)
        self.setLayout(layout)

    def rejected(self):
        self.close()

    def accepted(self):
        self.conf.set_template_address(self.edit_template.toPlainText())
        self.conf.store()
        self.close()


class ScriptGenerator:
    def __init__(self, configuration: Configuration) -> None:
        self.conf = configuration
        self.imagebase = idaapi.get_imagebase()

    @staticmethod
    def get_idb_filename():
        return os.path.basename(idaapi.get_input_file_path())

    @staticmethod
    def get_idb_path():
        return os.path.dirname(idaapi.get_input_file_path())

    def get_function_name(self,
                          ea):  # https://hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml
        """
        Get the real function name
        """
        # Try to demangle
        function_name = idc.demangle_name(idc.get_func_name(ea), idc.get_inf_attr(idc.INF_SHORT_DN))

        # if function_name:
        #    function_name = function_name.split("(")[0]

        # Function name is not mangled
        if not function_name:
            function_name = idc.get_func_name(ea)

        if not function_name:
            function_name = idc.get_name(ea, ida_name.GN_VISIBLE)

        # If we still have no function name, make one up. Format is - 'UNKN_FNC_4120000'
        if not function_name:
            function_name = "UNKN_FNC_%s" % hex(ea)

        return function_name

    def generate_func_stub(self, repdata: dict):
        s = self.conf.template_func
        for key, v in repdata.items():
            s = s.replace("[%s]" % key, v)
        return s

    def generate_address_stub(self, repdata: dict):
        s = self.conf.template_address
        for key, v in repdata.items():
            s = s.replace("[%s]" % key, v)
        return s

    def generate_for_funcs(self, func_addr_list) -> str:
        stubs = []
        for func_addr in func_addr_list:
            dec_func = idaapi.decompile(func_addr)
            repdata = {
                "filename": self.get_idb_filename(),
                "funcname": self.get_function_name(func_addr),
                "offset": hex(func_addr - self.imagebase),
                "nargs": hex(dec_func.type.get_nargs())
            }
            stubs.append(self.generate_func_stub(repdata))
        return "\n".join(stubs)

    def generate_for_address(self, address, registers) -> str:
        repdata = {
            "filename": self.get_idb_filename(),
            "address": hex(address - self.imagebase),
            "registers": registers
        }
        return self.generate_address_stub(repdata)

    def generate_for_funcs_to_file(self, func_addr_list, filename) -> bool:
        data = self.generate_for_funcs(func_addr_list)
        try:
            open(filename, "w").write(data)
            print("The generated Frida script has been exported to the file: ", filename)
        except Exception as e:
            print(e)
            return False
        try:
            QApplication.clipboard().setText(data)
            print("The generated Frida script has been copied to the clipboard!")
        except Exception as e:
            print(e)
            return False
        return True

    def generate_for_address_to_file(self, address, registers, filename) -> bool:
        data = self.generate_for_address(address, registers)
        try:
            open(filename, "w").write(data)
            print("The generated Frida script has been exported to the file: ", filename)
        except Exception as e:
            print(e)
            return False
        try:
            QApplication.clipboard().setText(data)
            print("The generated Frida script has been copied to the clipboard!")
        except Exception as e:
            print(e)
            return False
        return True


class Frida:
    def __init__(self, conf: Configuration) -> None:
        self.conf = conf


class IDAFridaMenuAction(Action):
    TopDescription = "IDAFrida"

    def __init__(self):
        super(IDAFridaMenuAction, self).__init__()

    def activate(self, ctx) -> None:
        raise NotImplemented

    def update(self, ctx) -> None:
        if ctx.widget_type == idaapi.BWN_FUNCS or ctx.widget_type == idaapi.BWN_PSEUDOCODE or ctx.widget_type == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(ctx.widget, None, self.name, self.TopDescription + "/")
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET


class InputRegistersUI(QDialog):
    def __init__(self) -> None:
        super(InputRegistersUI, self).__init__()
        self.setWindowTitle("Please enter the registers separated by spaces")
        self.setFixedWidth(600)
        self.edit_template = QLineEdit()
        self.edit_template.setClearButtonEnabled(True)
        self.edit_template.setPlaceholderText("eg: x0 x1 x2 x3....")
        layout = QVBoxLayout()
        btn_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        btn_box.setCenterButtons(True)
        
        btn_box.accepted.connect(self.accept_and_generate)
        btn_box.rejected.connect(self.reject)
        
        layout.addWidget(self.edit_template)
        layout.addWidget(btn_box)
        self.setLayout(layout)

    def accept_and_generate(self):
        """Handle the accepted signal and generate the script"""
        gen = ScriptGenerator(global_config)
        idb_path = os.path.dirname(idaapi.get_input_file_path())
        out_file = os.path.join(idb_path, "IDAhook.js")
        text = self.edit_template.text()
        text = text.strip()
        gen.generate_for_address_to_file(idaapi.get_screen_ea(), text, out_file)
        self.accept()

    def reject(self):
        """Handle the rejected signal"""
        super().reject()


class GenerateFridaHookScript(IDAFridaMenuAction):
    description = "Generate Frida Script on current func"

    def __init__(self):
        super(GenerateFridaHookScript, self).__init__()

    def activate(self, ctx):
        gen = ScriptGenerator(global_config)
        idb_path = os.path.dirname(idaapi.get_input_file_path())
        out_file = os.path.join(idb_path, "IDAhook.js")
        if ctx.widget_type == idaapi.BWN_FUNCS:
            selected = [idaapi.getn_func(idx).start_ea for idx in
                        ctx.chooser_selection]  # from "idaapi.getn_func(idx - 1)" to "idaapi.getn_func(idx)"
        else:
            selected = [idaapi.get_func(idaapi.get_screen_ea()).start_ea]
        gen.generate_for_funcs_to_file(selected, out_file)


class GenerateFridaHookScriptOnCurrentAddress(IDAFridaMenuAction):
    description = "Generate Frida Script on current address"

    def __init__(self):
        super(GenerateFridaHookScriptOnCurrentAddress, self).__init__()

    def activate(self, ctx):
        ui = InputRegistersUI()
        ui.show()
        ui.exec()

    def update(self, ctx) -> None:
        if ctx.widget_type == idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(ctx.widget, None, self.name, self.TopDescription + "/")
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET


class RunGeneratedScript(IDAFridaMenuAction):
    description = "Run Generated Script"

    def __init__(self):
        super(RunGeneratedScript, self).__init__()

    def activate(self, ctx):
        print("template")


class ViewFridaTemplateFunc(IDAFridaMenuAction):
    description = "View Frida func hook Template"

    def __init__(self):
        super(ViewFridaTemplateFunc, self).__init__()

    def activate(self, ctx):
        ui = FuncConfigurationUI(global_config)
        ui.show()
        ui.exec()


class ViewFridaTemplateAddress(IDAFridaMenuAction):
    description = "View Frida address hook Template"

    def __init__(self):
        super(ViewFridaTemplateAddress, self).__init__()

    def activate(self, ctx):
        ui = AddressConfigurationUI(global_config)
        ui.show()
        ui.exec()


class SetFridaRunCommand(IDAFridaMenuAction):
    description = "Set Frida Command"

    def __init__(self):
        super(SetFridaRunCommand, self).__init__()

    def activate(self, ctx):
        print("template")


action_manager.register(GenerateFridaHookScript())
action_manager.register(GenerateFridaHookScriptOnCurrentAddress())
# action_manager.register(RunGeneratedScript())
action_manager.register(ViewFridaTemplateFunc())
action_manager.register(ViewFridaTemplateAddress())
# action_manager.register(SetFridaRunCommand())

