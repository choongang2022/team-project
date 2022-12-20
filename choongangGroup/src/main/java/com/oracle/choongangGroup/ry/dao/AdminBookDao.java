package com.oracle.choongangGroup.ry.dao;

import java.util.List;

import com.oracle.choongangGroup.ry.model.BookCateVo;
import com.oracle.choongangGroup.ry.model.BookVo;

public interface AdminBookDao {


	List<BookCateVo> category();

	void bookInsert(BookVo book);

	List<BookVo> bookList(BookVo book);

	BookVo detailBookList(int bookId);

	BookVo updateBookGet(int bookId);

	void updateBookPost(BookVo book);

	void deleteBook(int bookId);

	List<BookVo> bookSearchList(BookVo book);

	int processTotal();

}
