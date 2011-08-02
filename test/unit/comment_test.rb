require 'test_helper'

class CommentTest < ActiveSupport::TestCase
  # Replace this with your real tests.
  test "the truth" do
    assert true
  end

  test "can be saved, loaded, and destroyed with special characters" do
    test_string = 'test: 𐅵𐅷𐅸 "𐅵𐅷𐅸" και 𐅵𐅷𐅸`\';"\\ / -- "𐅵𐅷𐅸 # 𐅵𐅷𐅸 <html>𐅵𐅷𐅸</html> <name value="test"/>'
    test_comment = Comment.new(:comment => test_string)

    assert_difference('Comment.count', 1) do
      test_comment.save!
    end

    assert_equal test_string, Comment.last.comment

    assert_difference('Comment.count', -1) do
      test_comment.destroy
    end
  end
end
