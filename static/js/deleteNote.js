function deletenote(element, id, redirect = "") {
    element.innerHTML = "Are you sure?";
    if (redirect == "") {
        link = `/deletenote?note_id=${id}`
    } else {
        link = `/deletenote?note_id=${id}&redirect=${redirect}`
    }
    element.setAttribute("href", link);
    element.removeAttribute("onclick");
}