function deletenote(element, id, redirect = "") {
    element.innerHTML = "Are you sure?";

    link = `/deletenote?note_id=${id}`
    if (redirect !== "") {
        link += `&redirect=${redirect}`
    }

    element.setAttribute("href", link);
    element.removeAttribute("onclick");
}