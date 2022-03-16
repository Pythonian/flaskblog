# Doctest Example

import doctest
import unittest

def sum_func(a, b):
    """
    Returns a + b

    >>> sum_func(10, 20)
    30
    >>> sum_func(-10, -20)
    -30
    >>> sum_func(10, -20)
    -10
    """
    return a + b


class TestSumFunc(unittest.TestCase):
    def test_sum_with_positive_number(self):
        result = sum_func(10, 20)
        self.assertEqual(result, 30)

    def test_sum_with_negative_number(self):
        result = sum_func(-10, -20)
        self.assertEqual(result, -30)

    def test_sum_with_mixed_signal_number(self):
        result = sum_func(10, -20)
        self.assertEqual(result, -10)


class PostDetailTest(BaseTest, TestCase):
    def add_single_post(self):
        from blog import Post
        db.session.add(Post(title='Some text', slug='some-text',
        content='some content'))
        db.session.commit()
        assert Post.query.count() == 1

    def setUp(self):
        super(PostDetailTest, self).setUp()
        self.add_single_post()

    def test_get_request(self):
        with self.app.test_request_context():
            url = url_for('blog.posts_view', slug='some-text')
            resp = self.client.get(url)
            self.assert200(resp)
            self.assertTemplateUsed('post.html')
            self.assertIn('Some text', resp.data)


class PostListTest(BaseTest, TestCase):
    def add_posts(self):
        from blog import Post
        db.session.add_all([
        Post(title='Some text', slug='some-text',
        content='some content'),
        Post(title='Some more text', slug='some-more-text',
        content='some more content'),
        Post(title='Here we go', slug='here-we-go',
        content='here we go!'),
        ])
        db.session.commit()
        assert Post.query.count() == 3

    def add_multiple_posts(self, count):
        from blog import Post
        db.session.add_all([
            Post(title='%d' % i, slug='%d' % i, content='content %d' % i) for i in range(count)])
        db.session.commit()
        assert Post.query.count() == count

    def test_get_posts(self):
        self.add_posts()
        # as we want to use url_for ...
        with self.app.test_request_context():
            url = url_for('blog.posts_view')
            resp = self.client.get(url)
            self.assert200(resp)
            self.assertIn('Some text', resp.data)
            self.assertIn('Some more text', resp.data)
            self.assertIn('Here we go', resp.data)
            self.assertTemplateUsed('posts.html')


if __name__ == '__main__':
    doctest.testmod(verbose=1)
    unittest.main()
    