/* 

Example Javascript Animation Techniques by Hesido.com;
4 different, reusable examples

*/
if (document.getElementById && document.getElementsByTagName) {
if (window.addEventListener) window.addEventListener('load', initAnims, false);
else if (window.attachEvent) window.attachEvent('onload', initAnims);
}

function initAnims() {
		var moveIt = document.getElementById('moveit');
		if (moveIt != null) moveIt.onclick = moveToBottom;
		
		function moveToBottom() {
			if (!this.currentPos) this.currentPos = [15,15]; 
			doPosChangeMem(this,this.currentPos,[Math.floor(Math.random()*1130+15),Math.floor(Math.random()*545)+15],20,20,0.5);
					}
}


function doPosChangeMem(elem,startPos,endPos,steps,intervals,powr) {
	if (elem.posChangeMemInt) window.clearInterval(elem.posChangeMemInt);
	var actStep = 0;
	elem.posChangeMemInt = window.setInterval(
		function() {
			elem.currentPos = [
				easeInOut(startPos[0],endPos[0],steps,actStep,powr),
				easeInOut(startPos[1],endPos[1],steps,actStep,powr)
				];
			elem.style.left = elem.currentPos[0]+"px";
			elem.style.top = elem.currentPos[1]+"px";
			actStep++;
			if (actStep > steps) window.clearInterval(elem.posChangeMemInt);
		}
		,intervals)

}



function easeInOut(minValue,maxValue,totalSteps,actualStep,powr) {

	var delta = maxValue - minValue;
	var stepp = minValue+(Math.pow(((1 / totalSteps)*actualStep),powr)*delta);
	return Math.ceil(stepp)
}
