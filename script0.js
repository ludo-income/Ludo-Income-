(function(){
  var mobileDevice = /Android|iPhone|iPad|iPod|Mobile/i.test(navigator.userAgent) || (window.matchMedia && window.matchMedia("(pointer:coarse)").matches) || (screen && screen.width <= 600);
  if(mobileDevice){ document.documentElement.classList.add("mobile-device"); }
})();