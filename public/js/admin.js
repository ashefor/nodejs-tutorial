const deleteProduct = (btn) => {
    const prodId = btn.parentNode.querySelector('[name=productId]').value;
    const csrfToken = btn.parentNode.querySelector('[name=_csrf]').value;

    const productElement = btn.closest('article');
    fetch('/admin/products/' + prodId, {
        method: 'DELETE',
        headers: {
            'csrf-token': csrfToken
        }
    }).then((result) => {
        return result.json();
    }).then(() => {
        // productElement.remove()
        productElement.parentNode.removeChild(productElement);
    }).catch(err => {
        console.log(err);
    })
}