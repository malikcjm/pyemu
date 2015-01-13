function showMenu(eventObj, nr) {
  eventObj.cancelBubble = true;
  if(changeObjectVisibility('flexMenuContent' + nr, 'visible')) {
    return true;
  } else {
    return false;
  }
}

function hideMenu(eventObj, nr) {
  eventObj.cancelBubble = true;
  if(changeObjectVisibility('flexMenuContent' + nr, 'hidden')) {
    return true;
  } else {
    return false;
  }
}

/**
 * Cross-browser function to get an object's style object given its id
 */
function getStyleObject(objectId) {
    if(document.getElementById && document.getElementById(objectId)) {
	// W3C DOM
	return document.getElementById(objectId).style;
    } else if (document.all && document.all(objectId)) {
	// MSIE 4 DOM
	return document.all(objectId).style;
    } else if (document.layers && document.layers[objectId]) {
	// NN 4 DOM.. note: this won't find nested layers
	return document.layers[objectId];
    } else {
	return false;
    }
}

/**
 * Get a reference to the cross-browser style object and make sure the object exists
 */
function changeObjectVisibility(objectId, newVisibility) {
  var styleObject = getStyleObject(objectId);
  if(styleObject) {
    styleObject.visibility = newVisibility;
    return true;
  } else {
    return false;
  }
}
