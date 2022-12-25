package com.oracle.choongangGroup.ry.service;

import java.util.List;

import com.oracle.choongangGroup.ry.model.BookCateVo;
import com.oracle.choongangGroup.ry.model.BookVo;

public interface AdminBookService {

	List<BookCateVo> category();

	void bookInsert(BookVo book);

	List<BookVo> bookList();

	BookVo bookDetailList(int bookId);

	BookVo updateBook(int bookId);

	void bookUpdate(BookVo book);

	void bookDelete(int bookId);

	List<BookVo> bookSearchList(BookVo book);
	}
