console.log("[Script] trace.js load")
var func = Module.getExportByName(null, "LoadLibraryA");
console.log("hook func:" + func)

Interceptor.attach(func, {
    onEnter: function(args){
		let stack = Thread.backtrace(this.context, Backtracer.ACCURATE)
		//console.log('Called from: ' + stack+"\n");
		send(stack)
		Thread.sleep(0.5)
	},
	onLeave: function(retval)
	{
        //console.log("ret var: " + retval)
    }
});
