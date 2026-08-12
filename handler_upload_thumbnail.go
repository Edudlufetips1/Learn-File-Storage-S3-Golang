package main

import (
	"fmt"
	"io"
	"net/http"

	"github.com/bootdotdev/learn-file-storage-s3-golang-starter/internal/auth"
	"github.com/google/uuid"
)

func (cfg *apiConfig) handlerUploadThumbnail(w http.ResponseWriter, r *http.Request) {
	const maxMemory = 10 << 20
	r.ParseMultipartForm(maxMemory)

	file, header, err := r.FormFile("thumbnail")
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Couldn't read thumbnail file", err)
		return
	}
	defer file.Close()

	mediaType := header.Header.Get("Content-Type")
	mediaData, err := io.ReadAll(file)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Couldn't read thumbnail data", err)
		return
	}

	token, err := auth.GetBearerToken(r.Header)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't find JWT", err)
		return
	}

	videoIDString := r.PathValue("videoID")
	videoID, err := uuid.Parse(videoIDString)

	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid ID", err)
		return
	}

	metaData, err := cfg.db.GetVideo(videoID)
	if err != nil {
		respondWithError(w, http.StatusNotFound, "Couldn't retrieve video data", err)
		return
	}

	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, http.StatusUnauthorized, "Couldn't validate JWT", err)
		return
	}
	if userID != metaData.UserID {
		respondWithError(w, http.StatusUnauthorized, "Thumbnail does not belong to user", nil)
		return
	}

	var videoThumbnail = thumbnail{
		data:      mediaData,
		mediaType: mediaType,
	}
	videoThumbnails[videoID] = videoThumbnail

	fmt.Println("uploading thumbnail for video", videoID, "by user", userID)
	url := fmt.Sprintf("http://localhost:%s/api/thumbnails/%s", cfg.port, videoID)
	metaData.ThumbnailURL = &url

	err = cfg.db.UpdateVideo(metaData)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Couldn't update video data", err)
		return
	}
	respondWithJSON(w, http.StatusOK, metaData)
}
